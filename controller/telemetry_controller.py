import json
import os

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import switches, api, event
from ryu import cfg

CONF = cfg.CONF
CONF.set_default('observe_links', True)


class TelemetryController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'switches': switches.Switches
    }

    def __init__(self, *args, **kwargs):

        super(TelemetryController, self).__init__(*args, **kwargs)

        # MAC learning table
        self.mac_to_port = {}

        # Connected datapaths
        self.datapaths = {}

        # Telemetry data
        self.telemetry = {
            "switches": {},
            "links": []
        }

        # Telemetry output file
        self.output_file = os.path.expanduser(
            "~/netops_guardrail/telemetry/data/latest.json"
        )

        # Start statistics monitoring thread
        self.monitor_thread = hub.spawn(
            self._monitor
        )

    # ==========================================================
    # SWITCH CONNECTION + TABLE-MISS FLOW
    # ==========================================================

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Save datapath
        self.datapaths[datapath.id] = datapath

        # Initialize telemetry entry
        self.telemetry["switches"].setdefault(
            str(datapath.id),
            {
                "ports": {},
                "flows": []
            }
        )

        self.logger.info(
            "SWITCH CONNECTED: datapath_id=%s",
            datapath.id
        )

        # Request initial stats on connection
        self._request_stats(datapath)

        # ------------------------------------------------------
        # Install table-miss flow.
        #
        # Unknown packets are sent to the controller.
        # ------------------------------------------------------

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath,
            0,
            match,
            actions
        )

    # ==========================================================
    # ADD FLOW
    # ==========================================================

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions
    ):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(flow_mod)

    # ==========================================================
    # PACKET-IN / L2 LEARNING SWITCH
    # ==========================================================

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        msg = ev.msg

        datapath = msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]

        # Parse Ethernet packet
        pkt = packet.Packet(msg.data)

        eth_packets = pkt.get_protocols(
            ethernet.ethernet
        )

        # Ignore packets without Ethernet header
        if not eth_packets:
            return

        eth = eth_packets[0]

        # Ignore LLDP packets in L2 learning (handled by switches.Switches)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        # ------------------------------------------------------
        # Learn source MAC address
        # ------------------------------------------------------

        self.mac_to_port.setdefault(
            dpid,
            {}
        )

        self.mac_to_port[dpid][src] = in_port

        # ------------------------------------------------------
        # Determine output port
        # ------------------------------------------------------

        out_port = self.mac_to_port[dpid].get(
            dst,
            ofproto.OFPP_FLOOD
        )

        actions = [
            parser.OFPActionOutput(
                out_port
            )
        ]

        # ------------------------------------------------------
        # Install learned flow
        # ------------------------------------------------------

        if out_port != ofproto.OFPP_FLOOD:

            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst
            )

            self.add_flow(
                datapath,
                1,
                match,
                actions
            )

        # ------------------------------------------------------
        # Send packet back through switch
        # ------------------------------------------------------

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:

            data = msg.data

        else:

            data = None

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

    # ==========================================================
    # SWITCH STATE CHANGE
    # ==========================================================

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER]
    )
    def state_change_handler(self, ev):

        datapath = ev.datapath

        self.logger.info(
            "SWITCH STATE CHANGE: datapath_id=%s",
            datapath.id
        )

    # ==========================================================
    # TELEMETRY MONITOR
    # ==========================================================

    def _monitor(self):

        while True:

            for datapath in list(self.datapaths.values()):

                self._request_stats(
                    datapath
                )

            self._update_links()

            hub.sleep(5)

    # ==========================================================
    # REQUEST FLOW + PORT STATISTICS
    # ==========================================================

    def _request_stats(self, datapath):

        self.logger.info(
            "REQUESTING STATS: datapath_id=%s",
            datapath.id
        )

        # Flow statistics
        flow_req = (
            datapath.ofproto_parser
            .OFPFlowStatsRequest(datapath)
        )

        datapath.send_msg(
            flow_req
        )

        # Port statistics
        port_req = (
            datapath.ofproto_parser
            .OFPPortStatsRequest(
                datapath,
                0
            )
        )

        datapath.send_msg(
            port_req
        )

    # ==========================================================
    # FLOW STATISTICS RESPONSE
    # ==========================================================

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER
    )
    def flow_stats_reply_handler(self, ev):

        datapath = ev.msg.datapath

        switch_id = str(
            datapath.id
        )

        flows = []

        for stat in ev.msg.body:

            flows.append(
                {
                    "priority": stat.priority,
                    "packet_count": stat.packet_count,
                    "byte_count": stat.byte_count
                }
            )

        self.telemetry[
            "switches"
        ][switch_id]["flows"] = flows

        self._write_telemetry()

        self.logger.info(
            "FLOW STATS: switch=%s entries=%d",
            datapath.id,
            len(flows)
        )

    # ==========================================================
    # PORT STATISTICS RESPONSE
    # ==========================================================

    @set_ev_cls(
        ofp_event.EventOFPPortStatsReply,
        MAIN_DISPATCHER
    )
    def port_stats_reply_handler(self, ev):

        datapath = ev.msg.datapath

        switch_id = str(
            datapath.id
        )

        ports = {}

        for stat in ev.msg.body:

            ports[str(stat.port_no)] = {
                "rx_packets": stat.rx_packets,
                "tx_packets": stat.tx_packets,
                "rx_bytes": stat.rx_bytes,
                "tx_bytes": stat.tx_bytes
            }

        self.telemetry[
            "switches"
        ][switch_id]["ports"] = ports

        self._write_telemetry()

    # ==========================================================
    # WRITE TELEMETRY JSON
    # ==========================================================

    def _write_telemetry(self):

        with open(
            self.output_file,
            "w"
        ) as file:

            json.dump(
                self.telemetry,
                file,
                indent=4
            )

    # ==========================================================
    # LINK DISCOVERY / TOPOLOGY UPDATE
    # ==========================================================

    @set_ev_cls(
        [event.EventLinkAdd, event.EventLinkDelete],
        MAIN_DISPATCHER
    )
    def link_change_handler(self, ev):
        self._update_links()

    def _update_links(self):
        try:
            links = api.get_all_link(self)
        except Exception as e:
            self.logger.warning("Error discovering links: %s", e)
            return

        discovered_links = []
        for link in links:
            src_sw = str(link.src.dpid)
            src_port = str(link.src.port_no)
            dst_sw = str(link.dst.dpid)
            dst_port = str(link.dst.port_no)

            if src_port == "4294967294" or dst_port == "4294967294":
                continue

            entry = {
                "src_switch": src_sw,
                "src_port": src_port,
                "dst_switch": dst_sw,
                "dst_port": dst_port
            }

            if entry not in discovered_links:
                discovered_links.append(entry)

        self.telemetry["links"] = discovered_links
        self._write_telemetry()
