import json
import os
import re
import secrets
import subprocess
import sys

from netops_guardrail.netops_paths import NETOPS_HOME
from netops_guardrail.verifier.safety_verifier import (
    build_topology,
    get_access_endpoints,
    run_safety_checks,
    test_port_removal,
)
from netops_guardrail.audit.audit_trail import AuditTrail
from netops_guardrail.controller.human_verifier import HumanApprovalStore, ApprovalError


SUPPORTED_ACTIONS = {"no_action", "block", "reroute"}
LOCAL_PORT = "4294967294"
MAX_PHYSICAL_PORT = 4294967040


class RemediationExecutor:
    """
    Controlled Remediation Executor for Mininet / Open vSwitch.
    
    Guarantees:
    1. NEVER executes an intent unless explicitly APPROVED by the decision gate.
    2. NEVER calls LLMs or makes autonomous AI remediation decisions.
    3. Re-validates target switches and physical ports before execution (blocks LOCAL/reserved ports).
    4. Safe argument construction with zero shell interpolation.
    5. Rigorous post-execution verification: validates OVS flow table state and topology safety.
    """

    def __init__(
        self,
        telemetry_path=None,
        cmd_runner=None,
        audit_trail=None,
        topology_provider=None,
        connectivity_checker=None,
        require_connectivity_check=True,
        approval_store=None,
        require_human_approval=True,
    ):
        if telemetry_path is not None:
            self.telemetry_path = telemetry_path
        else:
            self.telemetry_path = str(
                NETOPS_HOME / "telemetry" / "data" / "latest.json"
            )
        self.cmd_runner = cmd_runner or self._default_cmd_runner
        self.audit_trail = audit_trail
        self.topology_provider = topology_provider
        self.connectivity_checker = connectivity_checker
        self.require_connectivity_check = bool(require_connectivity_check)
        self.require_human_approval = bool(require_human_approval)
        self.approval_store = approval_store or (
            HumanApprovalStore() if self.require_human_approval else None
        )

    @staticmethod
    def _default_cmd_runner(args):
        """Execute a command safely using subprocess without shell expansion."""
        try:
            res = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                check=False
            )
            return res.returncode, res.stdout, res.stderr
        except Exception as e:
            return -1, "", str(e)

    def validate_preconditions(self, intent, decision, verifier_result, approval_id=None):
        """
        Validate that the intent is strictly approved and targets valid network elements.
        Returns (is_valid: bool, error_message: str | None).
        """
        # 1. Decision Gate enforcement
        if decision != "APPROVED":
            return False, f"Refusing execution: intent was {decision}, not APPROVED"

        if not isinstance(verifier_result, dict) or not verifier_result.get("safe"):
            return False, "Refusing execution: verifier_result is not marked safe"

        if not isinstance(intent, dict):
            return False, "Refusing execution: malformed intent (not an object)"

        action = intent.get("action")
        if action not in SUPPORTED_ACTIONS:
            return False, f"Refusing execution: unsupported action '{action}'"
        if action == "reroute":
            return False, "Refusing reroute: forwarding-aware safety verification is not implemented"

        # Every approved operation, including no_action, requires a known
        # topology so that "safe" never means "we could not inspect the network".
        topology, required_hosts = self._get_topology(phase="pre")
        if topology is None:
            return False, "Unable to verify current topology; refusing execution (fail-closed)"

        if action == "no_action":
            return True, None

        # A network mutation requires a persisted, authenticated, exact-action
        # human approval. A caller-supplied APPROVED string is not sufficient.
        if action == "block" and self.require_human_approval:
            if not approval_id or self.approval_store is None:
                return False, "Refusing block: valid human approval is required"
            try:
                self.approval_store.validate_approved(
                    approval_id, intent, verifier_result, self.telemetry_path
                )
            except ApprovalError as exc:
                return False, f"Refusing block: human approval validation failed: {exc}"

        # An autonomous live block must have an environment-specific
        # host-to-host probe. Topology simulation alone cannot prove the data
        # plane remained healthy after an OpenFlow change.
        if (
            action == "block"
            and self.require_connectivity_check
            and self.connectivity_checker is None
        ):
            return False, (
                "Refusing block: live connectivity checker is required for "
                "network mutation when require_connectivity_check=True"
            )

        # For block and reroute: strict validation of switch and ports
        target_switch = intent.get("target_switch")
        from_port = intent.get("from_port")

        if not target_switch or not from_port:
            return False, "Missing required target_switch or from_port"

        # Validate switch identifier format
        target_switch_str = str(target_switch).strip()
        if not target_switch_str.isdigit():
            return False, f"Invalid target_switch identifier: '{target_switch}'"

        # Validate from_port
        from_port_str = str(from_port).strip()
        if not from_port_str.isdigit():
            return False, f"Invalid from_port identifier: '{from_port}'"

        if from_port_str == LOCAL_PORT:
            return False, f"Cannot execute on OpenFlow LOCAL port {LOCAL_PORT}"

        from_port_int = int(from_port_str)
        if from_port_int <= 0 or from_port_int >= MAX_PHYSICAL_PORT:
            return False, f"Port {from_port_int} is outside valid physical port range"

        # If reroute, validate to_port as well
        to_port_str = None
        if action == "reroute":
            to_port = intent.get("to_port")
            if not to_port:
                return False, "Missing required to_port for reroute"
            to_port_str = str(to_port).strip()
            if not to_port_str.isdigit():
                return False, f"Invalid to_port identifier: '{to_port}'"
            if to_port_str == LOCAL_PORT:
                return False, f"Cannot reroute to OpenFlow LOCAL port {LOCAL_PORT}"
            to_port_int = int(to_port_str)
            if to_port_int <= 0 or to_port_int >= MAX_PHYSICAL_PORT:
                return False, f"Port {to_port_int} is outside valid physical port range"

        # Validate that switch and ports exist in the known topology.
        sw_node = f"s{target_switch_str}"
        port_node = f"s{target_switch_str}-p{from_port_str}"

        if sw_node not in topology:
            return False, f"Target switch {sw_node} does not exist in topology"
        if port_node not in topology:
            return False, f"Target port {port_node} does not exist in topology"

        # A "block" action means isolating an inter-switch trunk, not
        # disconnecting a host access port. Enforce this even when a caller
        # supplies a required-host list that might omit the target endpoint.
        if action == "block" and port_node in get_access_endpoints(topology):
            return False, (
                f"Refusing block: {port_node} is an access endpoint; "
                "blocking it would isolate a host"
            )

        # Defense in depth: do not trust a caller-supplied {"safe": true}
        # result by itself; independently simulate the proposed port block.
        if action == "block":
            simulated = test_port_removal(
                topology, port_node, required_hosts=required_hosts
            )
            if not simulated.get("safe"):
                explanation = simulated.get("reason") or simulated.get("checks")
                return False, (
                    "Refusing block: executor safety simulation failed: "
                    f"{explanation}"
                )

        if action == "reroute" and to_port_str:
            to_port_node = f"s{target_switch_str}-p{to_port_str}"
            if to_port_node not in topology:
                return False, f"Target destination port {to_port_node} does not exist in topology"
            if to_port_str == from_port_str:
                return False, "Reroute source and destination ports must be different"

        return True, None

    def _get_topology(self, phase="pre"):
        """Retrieve topology graph and optional required_hosts endpoints."""
        if self.topology_provider is not None:
            try:
                try:
                    res = self.topology_provider(phase=phase)
                except TypeError:
                    res = self.topology_provider()
                if isinstance(res, tuple):
                    return res[0], res[1]
                return res, None
            except Exception:
                return None, None

        if os.path.exists(self.telemetry_path):
            try:
                with open(self.telemetry_path, "r") as f:
                    telem = json.load(f)
                return build_topology(telem), None
            except Exception:
                return None, None

        return None, None

    def execute(self, intent, decision, verifier_result, approval_id=None):
        """
        Execute an approved inter-switch trunk block as a transaction.

        Both ends of a trunk receive cookie-tagged drop rules. If either
        install, flow-table verification, topology check, or configured live
        connectivity check fails, all rules installed by this transaction are
        removed and their absence is verified.
        """
        valid, err = self.validate_preconditions(
            intent, decision, verifier_result, approval_id=approval_id
        )
        if not valid:
            return {
                "success": False,
                "action": intent.get("action") if isinstance(intent, dict) else None,
                "error": err,
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": f"Pre-execution rejection: {err}",
            }

        action = intent["action"]
        if action == "no_action":
            safety_ok, safety_msg = self._verify_topology_safety()
            return {
                "success": safety_ok,
                "action": "no_action",
                "change_verified": True,
                "safety_verified": safety_ok,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was required",
                "details": f"No-action post-check: {safety_msg}",
            }

        # Reroute remains disabled pending forwarding-aware verification.
        if action != "block":
            return {
                "success": False,
                "action": action,
                "error": f"Unsupported live execution action: {action}",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": "Only block and no_action are enabled",
            }

        sw_id = int(intent["target_switch"])
        from_port = int(intent["from_port"])
        bridge_name = f"s{sw_id}"
        source_node = f"s{sw_id}-p{from_port}"

        topology, _ = self._get_topology(phase="pre")
        if topology is None or source_node not in topology:
            return {
                "success": False,
                "action": action,
                "error": "Unable to re-read topology before execution; refusing mutation",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": "Fresh pre-execution topology is unavailable",
            }

        peer_nodes = [
            node for node in topology.neighbors(source_node)
            if topology.nodes[node].get("type") == "port" or "-p" in str(node)
        ]
        if len(peer_nodes) != 1:
            return {
                "success": False,
                "action": action,
                "error": (
                    f"Refusing block: {source_node} must have exactly one "
                    "inter-switch peer port"
                ),
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": f"Unexpected trunk peer count: {len(peer_nodes)}",
            }

        peer_match = re.fullmatch(r"s(\d+)-p(\d+)", str(peer_nodes[0]))
        if not peer_match:
            return {
                "success": False,
                "action": action,
                "error": f"Unable to parse peer port {peer_nodes[0]!r}; refusing mutation",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": "Peer-port identity validation failed",
            }
        peer_switch, peer_port = int(peer_match.group(1)), int(peer_match.group(2))

        # Block ingress on both physical ends, so the link is isolated in both
        # directions rather than merely dropping traffic entering one switch.
        target_ports = [
            (sw_id, from_port),
            (peer_switch, peer_port),
        ]
        if target_ports[0] == target_ports[1]:
            return {
                "success": False,
                "action": action,
                "error": "Source and peer identify the same physical port",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": "Invalid topology peer mapping",
            }

        # Preflight both bridge flow tables before changing either end.
        targets = []
        for target_switch, target_port in target_ports:
            bridge = f"s{target_switch}"
            rc, existing_flows, inspect_error = self._dump_flows(bridge)
            if rc != 0:
                message = inspect_error or existing_flows or "unknown ovs-ofctl error"
                return {
                    "success": False,
                    "action": action,
                    "error": (
                        f"Unable to inspect existing OVS flows on {bridge}; "
                        f"refusing mutation: {message}"
                    ),
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": False,
                    "rollback_success": None,
                    "rollback_details": "No network mutation was attempted",
                    "details": "Pre-change flow inspection failed",
                }
            conflict = self._find_conflicting_flow(existing_flows, target_port)
            if conflict is not None:
                return {
                    "success": False,
                    "action": action,
                    "error": (
                        f"Refusing to overwrite an existing table-0 priority-65500 "
                        f"rule on {bridge} for input port {target_port}: {conflict.strip()}"
                    ),
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": False,
                    "rollback_success": None,
                    "rollback_details": "No network mutation was attempted",
                    "details": "Conflicting OVS flow existed before remediation",
                }
            targets.append({
                "bridge": bridge,
                "switch": str(target_switch),
                "port": str(target_port),
                "cookie": secrets.randbits(64) or 1,
            })

        # Consume approval immediately before the first mutation. The store
        # rechecks expiry, exact intent/verifier payload, and current topology,
        # and marks it single-use before any OVS command is issued.
        if self.require_human_approval:
            try:
                self.approval_store.consume_approval(
                    approval_id, intent, verifier_result, self.telemetry_path
                )
            except ApprovalError as exc:
                return {
                    "success": False,
                    "action": action,
                    "error": f"Refusing block: human approval could not be consumed: {exc}",
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": False,
                    "rollback_success": None,
                    "rollback_details": "No network mutation was attempted",
                    "details": "Human approval was revalidated before execution",
                }

        # Install one uniquely tagged drop rule per end of the physical link.
        changes = []
        for target in targets:
            target["flow_spec"] = (
                f"cookie=0x{target['cookie']:016x},priority=65500,"
                f"in_port={target['port']},actions=drop"
            )
            changes.append(target)  # include this target before the command:
                                     # a failed command may have partially applied.
            cmd = [
                "sudo", "ovs-ofctl", "-O", "OpenFlow13",
                "add-flow", target["bridge"], target["flow_spec"],
            ]
            rc, out, err_msg = self.cmd_runner(cmd)
            if rc != 0:
                rollback_ok, rollback_msg = self._rollback_transaction(changes)
                return {
                    "success": False,
                    "action": action,
                    "error": (
                        f"OVS add-flow failed on {target['bridge']} port {target['port']}: "
                        f"{err_msg or out or 'no details'}. "
                        f"Rollback {'succeeded' if rollback_ok else 'FAILED'}: {rollback_msg}"
                    ),
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": True,
                    "rollback_success": rollback_ok,
                    "rollback_details": rollback_msg,
                    "target_ports": target_ports,
                    "details": err_msg or out or "OVS add-flow failed",
                }

        # Verify both rules specifically by their transaction cookies.
        for target in targets:
            verified, verify_msg = self._verify_ovs_change(
                target["bridge"],
                f"in_port={target['port']}",
                "drop",
                expected_cookie=target["cookie"],
            )
            if not verified:
                rollback_ok, rollback_msg = self._rollback_transaction(changes)
                return {
                    "success": False,
                    "action": action,
                    "error": (
                        f"Post-execution flow verification failed on "
                        f"{target['bridge']} port {target['port']}: {verify_msg}. "
                        f"Rollback {'succeeded' if rollback_ok else 'FAILED'}: {rollback_msg}"
                    ),
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": True,
                    "rollback_success": rollback_ok,
                    "rollback_details": rollback_msg,
                    "target_ports": target_ports,
                    "details": verify_msg,
                }

        safety_ok, safety_msg = self._verify_topology_safety()
        if not safety_ok:
            rollback_ok, rollback_msg = self._rollback_transaction(changes)
            return {
                "success": False,
                "action": action,
                "error": (
                    f"Post-execution safety verification failed: {safety_msg}. "
                    f"Rollback {'succeeded' if rollback_ok else 'FAILED'}: {rollback_msg}"
                ),
                "change_verified": True,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": True,
                "rollback_success": rollback_ok,
                "rollback_details": rollback_msg,
                "target_ports": target_ports,
                "details": f"Both endpoint rules were verified, but topology post-check failed: {safety_msg}",
            }

        connectivity_verified = None
        if self.connectivity_checker is not None:
            try:
                connectivity_verified = bool(self.connectivity_checker())
            except Exception as exc:
                connectivity_verified = False
                safety_msg += f"; connectivity checker raised: {exc}"

            if not connectivity_verified:
                rollback_ok, rollback_msg = self._rollback_transaction(changes)
                return {
                    "success": False,
                    "action": action,
                    "error": (
                        "Post-execution live connectivity check failed. "
                        f"Rollback {'succeeded' if rollback_ok else 'FAILED'}: {rollback_msg}"
                    ),
                    "change_verified": True,
                    "safety_verified": True,
                    "connectivity_verified": False,
                    "rollback_attempted": True,
                    "rollback_success": rollback_ok,
                    "rollback_details": rollback_msg,
                    "target_ports": target_ports,
                    "details": "At least one host-to-host reachability probe failed",
                }

        return {
            "success": True,
            "action": action,
            "target_switch": str(sw_id),
            "from_port": str(from_port),
            "target_ports": target_ports,
            "human_approval_id": approval_id if self.require_human_approval else None,
            "change_verified": True,
            "safety_verified": True,
            "connectivity_verified": connectivity_verified,
            "rollback_attempted": False,
            "rollback_success": None,
            "rollback_details": "No rollback required",
            "details": (
                "Both ends of the inter-switch trunk were blocked and verified. "
                f"Topology safety check: {safety_msg}. "
                + (
                    "Live host-to-host reachability verified."
                    if connectivity_verified is True
                    else "No live connectivity checker was configured; only topology-level checks ran."
                )
            ),
        }

    def _rollback_transaction(self, changes):
        """Roll back every flow added by a transaction, verifying each removal."""
        outcomes = []
        all_ok = True
        for change in reversed(changes):
            ok, message = self._rollback_flow(change["bridge"], change["cookie"])
            outcomes.append({
                "bridge": change["bridge"],
                "port": change["port"],
                "success": ok,
                "details": message,
            })
            all_ok = all_ok and ok
        return all_ok, json.dumps(outcomes, sort_keys=True)

    def _dump_flows(self, bridge_name):
        """Read an OVS flow table using an argument array (no shell expansion)."""
        return self.cmd_runner([
            "sudo", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge_name
        ])

    @staticmethod
    def _find_conflicting_flow(output, from_port):
        """Find an existing same-priority table-0 rule that could be overwritten."""
        for line in (output or "").splitlines():
            match_part = line.split("actions=", 1)[0]
            priority = re.search(r"\bpriority=(\d+)\b", match_part)
            table = re.search(r"\btable=(\d+)\b", match_part)
            in_port = re.search(r"\bin_port=(\d+)\b", match_part)
            table_id = int(table.group(1)) if table else 0
            if (
                priority and int(priority.group(1)) == 65500
                and table_id == 0
                and in_port and int(in_port.group(1)) == int(from_port)
            ):
                return line
        return None

    @staticmethod
    def _flow_cookie(line):
        """Extract a 64-bit flow cookie from OVS output, when present."""
        match = re.search(r"\bcookie=0x([0-9a-f]+)\b", line or "", re.IGNORECASE)
        return int(match.group(1), 16) if match else None

    def _rollback_flow(self, bridge_name, cookie):
        """Remove only this transaction's rule and verify that it is absent."""
        cookie_filter = f"cookie=0x{cookie:016x}/0xffffffffffffffff"
        cmd = [
            "sudo", "ovs-ofctl", "-O", "OpenFlow13",
            "del-flows", bridge_name, cookie_filter,
        ]
        rc, out, err = self.cmd_runner(cmd)
        if rc != 0:
            return False, f"OVS rejected cookie-scoped rollback: {err or out or 'no details'}"

        verify_rc, flows, verify_err = self._dump_flows(bridge_name)
        if verify_rc != 0:
            return False, (
                "Rollback command returned success but flow-table verification failed: "
                f"{verify_err or flows or 'no details'}"
            )

        remaining = [
            line for line in (flows or "").splitlines()
            if self._flow_cookie(line) == cookie
        ]
        if remaining:
            return False, (
                "Rollback verification failed; remediation flow remains in OVS: "
                + remaining[0].strip()
            )
        return True, f"Removed and verified absence of remediation cookie 0x{cookie:016x}"

    def _verify_ovs_change(
        self, bridge_name, expected_pattern, expected_action, expected_cookie=None
    ):
        """Require the newly created cookie, not just an unrelated matching rule."""
        rc, out, err = self._dump_flows(bridge_name)
        if rc != 0:
            return False, f"Failed to dump OVS flows: {err or out or 'no details'}"

        for line in (out or "").splitlines():
            if expected_pattern not in line or expected_action not in line:
                continue
            if expected_cookie is not None and self._flow_cookie(line) != expected_cookie:
                continue
            cookie_note = (
                f" (cookie=0x{expected_cookie:016x})"
                if expected_cookie is not None else ""
            )
            return True, (
                f"Found active flow matching {expected_pattern} -> "
                f"{expected_action}{cookie_note}"
            )

        cookie_note = (
            f" and cookie=0x{expected_cookie:016x}"
            if expected_cookie is not None else ""
        )
        return False, (
            f"Rule with {expected_pattern} and {expected_action}{cookie_note} "
            "not found in active OVS flow table"
        )

    def _verify_topology_safety(self):
        """Run deterministic topology checks against the current topology provider."""
        graph, req_hosts = self._get_topology(phase="post")
        if graph is None:
            return False, "Unable to verify current topology; treating as unsafe (fail-closed)"
        try:
            res = run_safety_checks(graph, required_hosts=req_hosts)
            if res.get("safe"):
                return True, "Topology safety checks passed"
            return False, f"Topology safety check reported issues: {res.get('checks')}"
        except Exception as e:
            return False, f"Topology check error: {e}"
