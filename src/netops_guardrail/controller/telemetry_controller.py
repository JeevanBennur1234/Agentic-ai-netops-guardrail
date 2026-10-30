import json
import os
import tempfile
from datetime import datetime, timezone

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib import stplib
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import switches, api, event
from ryu import cfg

CONF = cfg.CONF
CONF.set_default('observe_links', True)


class TelemetryController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'switches': switches.Switches,
        'stplib': stplib.Stp
    }

    def __init__(self, *args, **kwargs):

        super(TelemetryController, self).__init__(*args, **kwargs)

        # MAC learning table and spanning-tree controller.
        # A redundant L2 topology must not use unrestricted flooding on every
        # trunk: STP blocks one redundant path to prevent broadcast storms.
        self.mac_to_port = {}
        self.stp = kwargs['stplib']
        # Keep testbed convergence short and deterministic while respecting
        # the minimum 802.1D forward-delay timer. s1 wins root election.
        self.stp.set_config({
            1: {'bridge': {'priority': 0x8000, 'hello_time': 2,
                           'max_age': 6, 'fwd_delay': 4}},
            2: {'bridge': {'priority': 0x9000, 'hello_time': 2,
                           'max_age': 6, 'fwd_delay': 4}},
            # Keep the triangle test deterministic: s3 is always non-root.
            3: {'bridge': {'priority': 0xA000, 'hello_time': 2,
                           'max_age': 6, 'fwd_delay': 4}},
        })

        # Connected datapaths
        self.datapaths = {}

        # Telemetry data
        self.telemetry = {
            "switches": {},
            "links": []
        }

        # Write to this checkout by default, not the current user's home.
        # Ryu is commonly launched via sudo, where "~" resolves to /root and
        # silently splits the controller from the verifier's telemetry file.
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.output_file = os.environ.get(
            "NETOPS_TELEMETRY_PATH",
            os.path.join(project_root, "telemetry", "data", "latest.json"),
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

        # A datapath ID can reconnect after a Mininet topology is torn down
        # and recreated with the same switch/port numbers. Port-status DELETE
        # events from the previous session must not be reused as current link
        # state, or the verifier can classify a newly recreated trunk as MISSING.
        switch_key = str(datapath.id)
        switch_telemetry = self.telemetry["switches"].setdefault(
            switch_key,
            {"ports": {}, "flows": []}
        )
        switch_telemetry["port_status"] = {}

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
        stplib.EventPacketIn,
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

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        """Persist OpenFlow port-status changes so safety checks can distinguish
        a physically/link-down trunk from a merely STP-blocked trunk.
        This observes the event; it deliberately does not override STP.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        desc = msg.desc
        switch_id = str(datapath.id)
        port_id = str(desc.port_no)
        reason_names = {
            getattr(ofproto, "OFPPR_ADD", 0): "ADD",
            getattr(ofproto, "OFPPR_DELETE", 1): "DELETE",
            getattr(ofproto, "OFPPR_MODIFY", 2): "MODIFY",
        }
        reason = reason_names.get(msg.reason, f"UNKNOWN_{msg.reason}")
        config = int(getattr(desc, "config", 0))
        state = int(getattr(desc, "state", 0))
        admin_down = bool(config & getattr(ofproto, "OFPPC_PORT_DOWN", 1))
        link_down = bool(state & getattr(ofproto, "OFPPS_LINK_DOWN", 1))
        if reason == "DELETE":
            state_name = "MISSING"
        elif admin_down or link_down:
            state_name = "DOWN"
        else:
            state_name = "UP"

        self.telemetry["switches"].setdefault(
            switch_id, {"ports": {}, "flows": []}
        ).setdefault("port_status", {})[port_id] = {
            "state": state_name,
            "reason": reason,
            "link_down": link_down,
            "admin_down": admin_down,
        }
        self.logger.warning(
            "OPENFLOW PORT STATUS: switch=%s port=%s state=%s reason=%s link_down=%s admin_down=%s",
            switch_id, port_id, state_name, reason, link_down, admin_down
        )
        self._write_telemetry()

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

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def stp_port_state_change_handler(self, ev):
        """Persist STP forwarding/blocking state for observability."""
        states = {
            stplib.PORT_STATE_DISABLE: "DISABLE",
            stplib.PORT_STATE_BLOCK: "BLOCK",
            stplib.PORT_STATE_LISTEN: "LISTEN",
            stplib.PORT_STATE_LEARN: "LEARN",
            stplib.PORT_STATE_FORWARD: "FORWARD",
        }
        state_name = states.get(ev.port_state, f"UNKNOWN_{ev.port_state}")
        switch_id = str(ev.dp.id)
        port_id = str(ev.port_no)
        self.telemetry["switches"].setdefault(
            switch_id, {"ports": {}, "flows": []}
        )
        self.telemetry["switches"][switch_id].setdefault("stp_port_states", {})
        self.telemetry["switches"][switch_id]["stp_port_states"][port_id] = state_name
        self.logger.info(
            "STP PORT STATE: switch=%s port=%s state=%s",
            switch_id, port_id, state_name
        )
        self._write_telemetry()

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
        """Publish a fresh complete telemetry snapshot atomically for readers."""
        self.telemetry["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        output_dir = os.path.dirname(self.output_file)
        os.makedirs(output_dir, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(
            prefix=".latest-telemetry-",
            suffix=".tmp",
            dir=output_dir,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(self.telemetry, file, indent=4)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temp_path, self.output_file)
            # Ryu may run as root while the dashboard/verifier runs as the
            # project user. Keep telemetry readable but not writable by others.
            os.chmod(self.output_file, 0o644)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

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
