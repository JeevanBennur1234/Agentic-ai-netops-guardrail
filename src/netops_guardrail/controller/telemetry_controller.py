import json
import os
import tempfile
from datetime import datetime, timezone

from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub, stplib
from ryu.lib.packet import ether_types, ethernet, packet
from ryu.ofproto import ofproto_v1_3
from ryu.topology import api, event, switches

from netops_guardrail.controller.trunk_roles import derive_discovered_hosts, derive_trunk_roles

CONF = cfg.CONF
CONF.set_default('observe_links', True)


def _serialize_openflow_value(value):
    """Convert Ryu OpenFlow objects into JSON-safe telemetry values."""
    if hasattr(value, "to_jsondict"):
        return _serialize_openflow_value(value.to_jsondict())
    if isinstance(value, dict):
        return {
            str(key): _serialize_openflow_value(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_serialize_openflow_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


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
        # the minimum 802.1D forward-delay timer.
        # Spanning Tree Bridge Priorities:
        # s1: 0x8000 (32768) -> Root Bridge (lowest priority wins root election)
        # s2: 0x9000 (36864) -> Non-root bridge; s2:p1 root port facing s1; s2:p2 designated facing s4
        # s3: 0xA000 (40960) -> Non-root bridge; s3:p1 root port facing s1; s3:p2 designated facing s4
        # s4: 0xB000 (45056) -> Non-root bridge (highest ID).
        # In ring4:
        # - s1 is Root Bridge (all ports FORWARD).
        # - s4 has two equal-cost paths to root (cost 4000) via s2 (bridge 0x9000) and s3 (bridge 0xA000).
        #   Since s2 bridge priority 0x9000 < s3 bridge priority 0xA000, s4 chooses s4:p3 (facing s2)
        #   as its Root Port.
        # - s4:p4 (facing s3:p2) is Alternate / BLOCKED.
        # Documented Root: s1.
        # Documented Blocked Link: s3-p2 <-> s4-p4 (blocked at s4:p4).
        self.stp.set_config({
            1: {'bridge': {'priority': 0x8000, 'hello_time': 2,
                           'max_age': 6, 'fwd_delay': 4}},
            2: {'bridge': {'priority': 0x9000, 'hello_time': 2,
                           'max_age': 6, 'fwd_delay': 4}},
            3: {'bridge': {'priority': 0xA000, 'hello_time': 2,
                           'max_age': 6, 'fwd_delay': 4}},
            4: {'bridge': {'priority': 0xB000, 'hello_time': 2,
                           'max_age': 6, 'fwd_delay': 4}},
        })

        # Connected datapaths
        self.datapaths = {}

        # Telemetry data
        self.telemetry = {
            "switches": {},
            "links": [],
            "hosts": [],
            "trunk_roles": {},
            "link_events": [],
            "port_status_events": [],
            "mac_learning_events": [],
        }

        # Write to this checkout by default, not the current user's home.
        # Ryu is commonly launched via sudo, where "~" resolves to /root and
        # silently splits the controller from the verifier's telemetry file.
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
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
        # A recreated Mininet topology reuses datapath IDs and port numbers.
        # Never let STP states from the previous bridge instance satisfy a
        # fresh test's convergence check.
        switch_telemetry["stp_port_states"] = {}

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

    def _flush_learning_state(self, reason):
        """Invalidate learned L2 paths after a topology/port transition."""
        mac_table = getattr(self, "mac_to_port", {})
        learned_macs = {
            mac
            for table in mac_table.values()
            for mac in table
        }
        for datapath in list(getattr(self, "datapaths", {}).values()):
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            for mac in learned_macs:
                delete = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    table_id=0,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=parser.OFPMatch(eth_dst=mac),
                )
                datapath.send_msg(delete)
        if hasattr(self, "mac_to_port"):
            self.mac_to_port.clear()
        self.logger.warning("L2 LEARNING STATE FLUSHED: reason=%s", reason)

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

        is_new_source = src not in self.mac_to_port[dpid]
        self.mac_to_port[dpid][src] = in_port
        if is_new_source:
            switch_key = str(dpid)
            switch_data = self.telemetry["switches"].setdefault(
                switch_key, {"ports": {}, "flows": []}
            )
            switch_data["learned_mac_count"] = len(self.mac_to_port[dpid])
            self.telemetry["mac_learning_events"].append({
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "switch_id": switch_key,
                "source_mac": src,
                "port_id": str(in_port),
            })
            self.telemetry["mac_learning_events"] = (
                self.telemetry["mac_learning_events"][-2000:]
            )

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
        self.telemetry.setdefault("port_status_events", []).append({
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "switch_id": switch_id,
            "port_id": port_id,
            "state": state_name,
            "reason": reason,
            "link_down": link_down,
            "admin_down": admin_down,
        })
        self.telemetry["port_status_events"] = (
            self.telemetry["port_status_events"][-500:]
        )
        self.logger.warning(
            "OPENFLOW PORT STATUS: switch=%s port=%s state=%s reason=%s link_down=%s admin_down=%s",
            switch_id, port_id, state_name, reason, link_down, admin_down
        )
        if state_name in ("DOWN", "MISSING"):
            self._flush_learning_state(f"port-{state_name.lower()}:{switch_id}/{port_id}")
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
        if state_name in ("DISABLE", "FORWARD"):
            self._flush_learning_state(f"stp-{state_name.lower()}:{switch_id}/{port_id}")
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
                    "table_id": getattr(stat, "table_id", None),
                    "cookie": int(getattr(stat, "cookie", 0)),
                    "priority": stat.priority,
                    "match": _serialize_openflow_value(getattr(stat, "match", {})),
                    "instructions": _serialize_openflow_value(
                        getattr(stat, "instructions", [])
                    ),
                    "packet_count": stat.packet_count,
                    "byte_count": stat.byte_count,
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
        # Derive dynamic trunk roles and discovered hosts
        trunk_roles = derive_trunk_roles(self.telemetry)
        self.telemetry["trunk_roles"] = trunk_roles
        for link in self.telemetry.get("links", []):
            src_ep = f"s{link.get('src_switch')}-p{link.get('src_port')}"
            dst_ep = f"s{link.get('dst_switch')}-p{link.get('dst_port')}"
            pair = sorted([src_ep, dst_ep])
            if pair in trunk_roles.get("standby_trunks", []):
                link["role"] = "standby"
            elif pair in trunk_roles.get("primary_trunks", []):
                link["role"] = "primary"
            elif pair in [[d["src"], d["dst"]] for d in trunk_roles.get("links", []) if d.get("role") == "down"]:
                link["role"] = "down"
            else:
                link["role"] = "converging"
        self.telemetry["hosts"] = derive_discovered_hosts(self.telemetry)
        # Provenance is written by the telemetry producer, never accepted from
        # HTTP/request payloads. Lab injectors may override only through their
        # trusted controller-side event pipeline.
        self.telemetry.setdefault("provenance", {
            "source": "live_telemetry",
            "producer": "ryu_telemetry_controller",
        })
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
        link = getattr(ev, "link", None)
        if link is not None:
            event_name = "ADD" if "Add" in type(ev).__name__ else "DELETE"
            self.telemetry["link_events"].append({
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "event": event_name,
                "src_switch": str(link.src.dpid),
                "src_port": str(link.src.port_no),
                "dst_switch": str(link.dst.dpid),
                "dst_port": str(link.dst.port_no),
            })
            self.telemetry["link_events"] = self.telemetry["link_events"][-500:]
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
