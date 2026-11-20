import json
import os
import re
import secrets
import subprocess
import time

from netops_guardrail.controller.human_verifier import ApprovalError, HumanApprovalStore
from netops_guardrail.netops_paths import NETOPS_HOME
from netops_guardrail.verifier.safety_verifier import (
    ALLOWED_ACTIONS,
    MAX_RATE_LIMIT_KBPS,
    MIN_RATE_LIMIT_KBPS,
    MUTATION_ACTIONS,
    CorruptLedgerError,
    build_topology,
    get_access_endpoints,
    load_guardrail_cookies,
    matches_strictly_equal,
    normalize_match_dict,
    record_guardrail_cookie,
    remove_guardrail_cookie,
    run_safety_checks,
    simulate_disable_port,
    simulate_rate_limit_port,
    simulate_remove_flow,
    simulate_restore_port,
    test_port_removal,
    validate_intent_schema,
)

SUPPORTED_ACTIONS = ALLOWED_ACTIONS
MUTATION_ACTIONS = MUTATION_ACTIONS
EXECUTABLE_ACTIONS = MUTATION_ACTIONS
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
        convergence_window_seconds=25.0,
        ledger_path=None,
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
        self.convergence_window_seconds = float(convergence_window_seconds)
        self.ledger_path = str(ledger_path) if ledger_path else None

    @staticmethod
    def _parse_ovs_match_string(match_str: str) -> dict:
        """Parse match fields from an OVS flow line into a normalized dictionary."""
        return normalize_match_dict(match_str)

    def _wait_for_convergence(self, timeout=None, poll_interval=0.5):
        """
        Poll topology safety and live connectivity until both pass or window expires.
        Returns (converged: bool, elapsed_seconds: float, last_error: str | None).
        """
        window = self.convergence_window_seconds if timeout is None else float(timeout)
        start_time = time.monotonic()
        last_error = None

        while True:
            elapsed = time.monotonic() - start_time
            safety_ok, safety_msg = self._verify_topology_safety()
            if not safety_ok:
                last_error = f"Topology safety check failed: {safety_msg}"
            else:
                conn_ok = True
                if self.connectivity_checker is not None:
                    try:
                        conn_ok = bool(self.connectivity_checker())
                        if not conn_ok:
                            last_error = "Live connectivity checker failed"
                    except Exception as exc:
                        conn_ok = False
                        last_error = f"Connectivity checker raised: {exc}"
                if conn_ok:
                    return True, round(elapsed, 3), None

            if elapsed >= window:
                break
            time.sleep(min(poll_interval, max(0.01, window - elapsed)))

        total_elapsed = round(time.monotonic() - start_time, 3)
        return False, total_elapsed, last_error or f"Convergence window timed out after {window}s"

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

    def validate_preconditions(self, intent, decision, verifier_result, approval_id=None, incident_context=None):
        """
        Validate that the intent is strictly approved and targets valid network elements.
        Returns (is_valid: bool, error_message: str | None).
        """
        # 1. Decision Gate enforcement
        if decision != "APPROVED":
            return False, f"Refusing execution: intent was {decision}, not APPROVED"

        if not isinstance(verifier_result, dict) or not verifier_result.get("safe"):
            return False, "Refusing execution: verifier_result is not marked safe"

        # Strict intent schema validation (rejects extra keys, invalid types, strings in match)
        valid, schema_err = validate_intent_schema(intent)
        if not valid:
            return False, f"Refusing execution: invalid intent schema: {schema_err}"

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
        if action in MUTATION_ACTIONS and self.require_human_approval:
            if not approval_id or self.approval_store is None:
                return False, f"Refusing {action}: valid human approval is required"
            try:
                self.approval_store.validate_approved(
                    approval_id, intent, verifier_result, self.telemetry_path, incident_context=incident_context
                )
            except ApprovalError as exc:
                return False, f"Refusing {action}: human approval validation failed: {exc}"

        # An autonomous live mutation must have an environment-specific
        # host-to-host probe. Topology simulation alone cannot prove the data
        # plane remained healthy after an OpenFlow change.
        if (
            action in MUTATION_ACTIONS
            and self.require_connectivity_check
            and self.connectivity_checker is None
        ):
            return False, (
                f"Refusing {action}: live connectivity checker is required for "
                "network mutation when require_connectivity_check=True"
            )

        # For block and reroute: strict validation of switch and ports
        if action in {"block", "reroute"}:
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

        if action == "disable_port":
            target_switch = intent.get("target_switch") or intent.get("switch")
            from_port = intent.get("from_port") or intent.get("port")
            if not target_switch or not from_port:
                return False, "Missing required target_switch or from_port for disable_port"

            target_switch_str = str(target_switch).strip()
            if not target_switch_str.isdigit():
                return False, f"Invalid target_switch identifier: '{target_switch}'"

            from_port_str = str(from_port).strip()
            if not from_port_str.isdigit():
                return False, f"Invalid from_port identifier: '{from_port}'"

            if from_port_str == LOCAL_PORT:
                return False, f"Cannot execute on OpenFlow LOCAL port {LOCAL_PORT}"

            from_port_int = int(from_port_str)
            if from_port_int <= 0 or from_port_int >= MAX_PHYSICAL_PORT:
                return False, f"Port {from_port_int} is outside valid physical port range"

            sw_node = f"s{target_switch_str}"
            port_node = f"s{target_switch_str}-p{from_port_str}"

            if sw_node not in topology:
                return False, f"Target switch {sw_node} does not exist in topology"
            if port_node not in topology:
                return False, f"Target port {port_node} does not exist in topology"

            if port_node in get_access_endpoints(topology):
                return False, (
                    f"Refusing disable_port: {port_node} is an access endpoint; "
                    "disabling it isolates that host"
                )

            simulated = simulate_disable_port(
                topology, target_switch_str, from_port_str,
                required_hosts=required_hosts, require_loop_free=True
            )
            if not simulated.get("safe"):
                explanation = simulated.get("reason") or simulated.get("checks")
                return False, f"Refusing disable_port: executor safety simulation failed: {explanation}"

        if action == "restore_port":
            target_switch = intent.get("target_switch") or intent.get("switch")
            from_port = intent.get("from_port") or intent.get("port")
            if not target_switch or not from_port:
                return False, "Missing required target_switch or from_port for restore_port"

            target_switch_str = str(target_switch).strip()
            if not target_switch_str.isdigit():
                return False, f"Invalid target_switch identifier: '{target_switch}'"

            from_port_str = str(from_port).strip()
            if not from_port_str.isdigit():
                return False, f"Invalid from_port identifier: '{from_port}'"

            if from_port_str == LOCAL_PORT:
                return False, f"Cannot execute on OpenFlow LOCAL port {LOCAL_PORT}"

            from_port_int = int(from_port_str)
            if from_port_int <= 0 or from_port_int >= MAX_PHYSICAL_PORT:
                return False, f"Port {from_port_int} is outside valid physical port range"

            sw_node = f"s{target_switch_str}"
            port_node = f"s{target_switch_str}-p{from_port_str}"

            if sw_node not in topology:
                return False, f"Target switch {sw_node} does not exist in topology"

            simulated = simulate_restore_port(
                topology, target_switch_str, from_port_str,
                required_hosts=required_hosts, require_loop_free=True
            )
            if not simulated.get("safe"):
                explanation = simulated.get("reason") or simulated.get("checks")
                return False, f"Refusing restore_port: executor safety simulation failed: {explanation}"

        if action == "remove_flow":
            target_switch = intent.get("target_switch") or intent.get("switch")
            cookie = intent.get("cookie")
            priority = intent.get("priority")
            match = intent.get("match")

            if not target_switch or cookie is None or priority is None or match is None:
                return False, "Missing required fields (target_switch, cookie, priority, match) for remove_flow"

            target_switch_str = str(target_switch).strip()
            if not target_switch_str.isdigit():
                return False, f"Invalid target_switch identifier: '{target_switch}'"
            sw_node = f"s{target_switch_str}"
            if sw_node not in topology:
                return False, f"Target switch {sw_node} does not exist in topology"

            try:
                cookie_int = int(str(cookie), 0)
                priority_int = int(str(priority))
            except (ValueError, TypeError):
                return False, "Invalid cookie or priority integer representation"

            if priority_int == 0:
                return False, "Refusing remove_flow: cannot delete table-miss baseline flow (priority 0)"
            if priority_int == 1 and cookie_int == 0:
                return False, "Refusing remove_flow: cannot delete baseline MAC learning flow (priority 1, cookie 0)"
            if cookie_int == 0:
                return False, "Refusing remove_flow: cannot delete baseline flow (cookie 0)"
            if priority_int == 65500:
                return False, "Refusing remove_flow: cannot delete active guardrail remediation drop rule (priority 65500)"

            # Check guardrail cookie ledger (fail closed if corrupt)
            try:
                ledger_cookies = load_guardrail_cookies(self.ledger_path)
            except CorruptLedgerError as exc:
                return False, f"Refusing remove_flow: guardrail ledger is unreadable or corrupt; failing closed: {exc}"

            if cookie_int in ledger_cookies:
                return False, f"Refusing remove_flow: cannot delete guardrail-installed rule (cookie 0x{cookie_int:x} present in guardrail ledger)"

            simulated = simulate_remove_flow(
                topology, intent, incident_context=incident_context,
                required_hosts=required_hosts, require_loop_free=True,
                ledger_path=self.ledger_path,
            )
            if not simulated.get("safe"):
                explanation = simulated.get("reason") or simulated.get("checks")
                return False, f"Refusing remove_flow: executor safety simulation failed: {explanation}"

        if action == "rate_limit_port":
            target_switch = intent.get("target_switch") or intent.get("switch")
            from_port = intent.get("from_port") or intent.get("port")
            rate_kbps = intent.get("rate_kbps")

            if not target_switch or not from_port or rate_kbps is None:
                return False, "Missing required fields (target_switch, from_port, rate_kbps) for rate_limit_port"

            target_switch_str = str(target_switch).strip()
            if not target_switch_str.isdigit():
                return False, f"Invalid target_switch identifier: '{target_switch}'"
            from_port_str = str(from_port).strip()
            if not from_port_str.isdigit():
                return False, f"Invalid from_port identifier: '{from_port}'"
            if from_port_str == LOCAL_PORT:
                return False, f"Cannot execute on OpenFlow LOCAL port {LOCAL_PORT}"
            from_port_int = int(from_port_str)
            if from_port_int <= 0 or from_port_int >= MAX_PHYSICAL_PORT:
                return False, f"Port {from_port_int} is outside valid physical port range"

            sw_node = f"s{target_switch_str}"
            port_node = f"s{target_switch_str}-p{from_port_str}"
            if sw_node not in topology:
                return False, f"Target switch {sw_node} does not exist in topology"
            if port_node not in topology:
                return False, f"Target port {port_node} does not exist in topology"

            if port_node not in get_access_endpoints(topology):
                return False, (
                    f"Refusing rate_limit_port: {port_node} is an inter-switch trunk; "
                    "rate limiting is permitted on access ports only"
                )

            try:
                rate_int = int(str(rate_kbps))
            except (ValueError, TypeError):
                return False, f"Invalid rate_kbps value: '{rate_kbps}'"

            if rate_int < MIN_RATE_LIMIT_KBPS or rate_int > MAX_RATE_LIMIT_KBPS:
                return False, f"Refusing rate_limit_port: rate {rate_int} kbps is outside allowed range [{MIN_RATE_LIMIT_KBPS}, {MAX_RATE_LIMIT_KBPS}] kbps"

            simulated = simulate_rate_limit_port(
                topology, intent, required_hosts=required_hosts, require_loop_free=True
            )
            if not simulated.get("safe"):
                explanation = simulated.get("reason") or simulated.get("checks")
                return False, f"Refusing rate_limit_port: executor safety simulation failed: {explanation}"

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

    def execute(self, intent, decision, verifier_result, approval_id=None, incident_context=None):
        """
        Execute an approved inter-switch trunk block as a transaction.

        Both ends of a trunk receive cookie-tagged drop rules. If either
        install, flow-table verification, topology check, or configured live
        connectivity check fails, all rules installed by this transaction are
        removed and their absence is verified.
        """
        if approval_id and incident_context is None and self.approval_store:
            try:
                proposal = self.approval_store.get_proposal(approval_id)
                if proposal:
                    incident_context = proposal.get("incident_context")
            except Exception:
                pass

        valid, err = self.validate_preconditions(
            intent, decision, verifier_result, approval_id=approval_id, incident_context=incident_context
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

        elif action == "block":
            return self._execute_block(intent, approval_id, verifier_result, incident_context=incident_context)
        elif action == "disable_port":
            return self._execute_disable_port(intent, approval_id, verifier_result, incident_context=incident_context)
        elif action == "restore_port":
            return self._execute_restore_port(intent, approval_id, verifier_result, incident_context=incident_context)
        elif action == "remove_flow":
            return self._execute_remove_flow(intent, approval_id, verifier_result, incident_context=incident_context)
        elif action == "rate_limit_port":
            return self._execute_rate_limit_port(intent, approval_id, verifier_result, incident_context=incident_context)
        else:
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
                "details": f"Action {action} is not enabled for live execution",
            }

    def _execute_block(self, intent, approval_id, verifier_result, incident_context=None):
        action = "block"
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
                    approval_id, intent, verifier_result, self.telemetry_path, incident_context=incident_context
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
            try:
                # Persist the cookie before issuing any OVS mutation.
                record_guardrail_cookie(
                    target["cookie"], action="block", bridge=target["bridge"], ledger_path=self.ledger_path
                )
            except Exception as exc:
                rollback_ok, rollback_msg = self._rollback_transaction(changes) if changes else (True, "No OVS changes were made")
                return {
                    "success": False, "action": action,
                    "error": f"Refusing block: guardrail ledger could not be persisted; failing closed: {exc}",
                    "change_verified": False, "safety_verified": False, "connectivity_verified": None,
                    "rollback_attempted": bool(changes),
                    "rollback_success": rollback_ok if changes else None,
                    "rollback_details": rollback_msg,
                    "details": "No untracked OVS flow was installed",
                }
            changes.append(target)  # OVS may partially apply even when the command fails.
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
        # Verify both rules specifically by their transaction cookies.\n        for target in targets:
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

    def _execute_disable_port(self, intent, approval_id, verifier_result, incident_context=None):
        sw_id = int(intent.get("target_switch") or intent.get("switch"))
        from_port = int(intent.get("from_port") or intent.get("port"))
        bridge = f"s{sw_id}"
        cookie = secrets.randbits(64) or 1

        if self.require_human_approval:
            try:
                self.approval_store.consume_approval(
                    approval_id, intent, verifier_result, self.telemetry_path, incident_context=incident_context
                )
            except ApprovalError as exc:
                return {
                    "success": False,
                    "action": "disable_port",
                    "error": f"Refusing disable_port: human approval could not be consumed: {exc}",
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": False,
                    "rollback_success": None,
                    "rollback_details": "No network mutation was attempted",
                    "details": "Human approval was revalidated before execution",
                }

        cmd = ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "mod-port", bridge, str(from_port), "down"]
        inverse_cmd = ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "mod-port", bridge, str(from_port), "up"]

        rc, out, err = self.cmd_runner(cmd)
        if rc != 0:
            rb_rc, rb_out, rb_err = self.cmd_runner(inverse_cmd)
            rollback_ok = (rb_rc == 0)
            return {
                "success": False,
                "action": "disable_port",
                "target_switch": str(sw_id),
                "from_port": str(from_port),
                "cookie": cookie,
                "inverse_command": inverse_cmd,
                "error": f"OVS mod-port down failed on {bridge} port {from_port}: {err or out or 'no details'}",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": True,
                "rollback_success": rollback_ok,
                "rollback_details": f"Inverse mod-port up executed (rc={rb_rc})",
                "details": err or out or "OVS mod-port down failed",
            }

        # Post-check 1: OVS port state
        rc_desc, out_desc, err_desc = self._dump_ports_desc(bridge)
        port_cfg = self._parse_port_config(out_desc, from_port)
        if rc_desc != 0 or not port_cfg.get("admin_down"):
            rb_rc, rb_out, rb_err = self.cmd_runner(inverse_cmd)
            rollback_ok = (rb_rc == 0)
            return {
                "success": False,
                "action": "disable_port",
                "target_switch": str(sw_id),
                "from_port": str(from_port),
                "cookie": cookie,
                "inverse_command": inverse_cmd,
                "error": f"Post-execution port verification failed on {bridge} port {from_port}: PORT_DOWN flag not detected",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": True,
                "rollback_success": rollback_ok,
                "rollback_details": f"Inverse mod-port up executed (rc={rb_rc})",
                "details": "Port status verification failed",
            }

        # Post-check 2: Convergence window polling (safety + live connectivity)
        converged, conv_time, conv_err = self._wait_for_convergence()
        if not converged:
            rb_rc, rb_out, rb_err = self.cmd_runner(inverse_cmd)
            rollback_ok = (rb_rc == 0)
            return {
                "success": False,
                "action": "disable_port",
                "target_switch": str(sw_id),
                "from_port": str(from_port),
                "cookie": cookie,
                "inverse_command": inverse_cmd,
                "convergence_time_seconds": conv_time,
                "error": f"Post-execution convergence failed within {self.convergence_window_seconds}s: {conv_err}. Rollback {'succeeded' if rollback_ok else 'FAILED'}",
                "change_verified": True,
                "safety_verified": False,
                "connectivity_verified": False if self.connectivity_checker is not None else None,
                "rollback_attempted": True,
                "rollback_success": rollback_ok,
                "rollback_details": f"Inverse mod-port up executed (rc={rb_rc})",
                "details": f"Convergence failure: {conv_err}",
            }

        return {
            "success": True,
            "action": "disable_port",
            "target_switch": str(sw_id),
            "from_port": str(from_port),
            "cookie": cookie,
            "inverse_command": inverse_cmd,
            "human_approval_id": approval_id if self.require_human_approval else None,
            "convergence_time_seconds": conv_time,
            "change_verified": True,
            "safety_verified": True,
            "connectivity_verified": True if self.connectivity_checker is not None else None,
            "rollback_attempted": False,
            "rollback_success": None,
            "rollback_details": "No rollback required",
            "details": f"Port {bridge}-p{from_port} admin-down verified. Converged in {conv_time}s.",
        }

    def _execute_restore_port(self, intent, approval_id, verifier_result, incident_context=None):
        sw_id = int(intent.get("target_switch") or intent.get("switch"))
        from_port = int(intent.get("from_port") or intent.get("port"))
        bridge = f"s{sw_id}"
        cookie = secrets.randbits(64) or 1

        if self.require_human_approval:
            try:
                self.approval_store.consume_approval(
                    approval_id, intent, verifier_result, self.telemetry_path, incident_context=incident_context
                )
            except ApprovalError as exc:
                return {
                    "success": False,
                    "action": "restore_port",
                    "error": f"Refusing restore_port: human approval could not be consumed: {exc}",
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": False,
                    "rollback_success": None,
                    "rollback_details": "No network mutation was attempted",
                    "details": "Human approval was revalidated before execution",
                }

        cmd = ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "mod-port", bridge, str(from_port), "up"]
        inverse_cmd = ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "mod-port", bridge, str(from_port), "down"]

        rc, out, err = self.cmd_runner(cmd)
        if rc != 0:
            rb_rc, rb_out, rb_err = self.cmd_runner(inverse_cmd)
            rollback_ok = (rb_rc == 0)
            return {
                "success": False,
                "action": "restore_port",
                "target_switch": str(sw_id),
                "from_port": str(from_port),
                "cookie": cookie,
                "inverse_command": inverse_cmd,
                "error": f"OVS mod-port up failed on {bridge} port {from_port}: {err or out or 'no details'}",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": True,
                "rollback_success": rollback_ok,
                "rollback_details": f"Inverse mod-port down executed (rc={rb_rc})",
                "details": err or out or "OVS mod-port up failed",
            }

        # Post-check 1: OVS port state (must not be admin_down)
        rc_desc, out_desc, err_desc = self._dump_ports_desc(bridge)
        port_cfg = self._parse_port_config(out_desc, from_port)
        if rc_desc != 0 or port_cfg.get("admin_down"):
            rb_rc, rb_out, rb_err = self.cmd_runner(inverse_cmd)
            rollback_ok = (rb_rc == 0)
            return {
                "success": False,
                "action": "restore_port",
                "target_switch": str(sw_id),
                "from_port": str(from_port),
                "cookie": cookie,
                "inverse_command": inverse_cmd,
                "error": f"Post-execution port verification failed on {bridge} port {from_port}: port remains PORT_DOWN",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": True,
                "rollback_success": rollback_ok,
                "rollback_details": f"Inverse mod-port down executed (rc={rb_rc})",
                "details": "Port status verification failed",
            }

        # Post-check 2: Convergence window polling (safety + live connectivity)
        converged, conv_time, conv_err = self._wait_for_convergence()
        if not converged:
            rb_rc, rb_out, rb_err = self.cmd_runner(inverse_cmd)
            rollback_ok = (rb_rc == 0)
            return {
                "success": False,
                "action": "restore_port",
                "target_switch": str(sw_id),
                "from_port": str(from_port),
                "cookie": cookie,
                "inverse_command": inverse_cmd,
                "convergence_time_seconds": conv_time,
                "error": f"Post-execution convergence failed within {self.convergence_window_seconds}s: {conv_err}. Rollback {'succeeded' if rollback_ok else 'FAILED'}",
                "change_verified": True,
                "safety_verified": False,
                "connectivity_verified": False if self.connectivity_checker is not None else None,
                "rollback_attempted": True,
                "rollback_success": rollback_ok,
                "rollback_details": f"Inverse mod-port down executed (rc={rb_rc})",
                "details": f"Convergence failure: {conv_err}",
            }

        return {
            "success": True,
            "action": "restore_port",
            "target_switch": str(sw_id),
            "from_port": str(from_port),
            "cookie": cookie,
            "inverse_command": inverse_cmd,
            "human_approval_id": approval_id if self.require_human_approval else None,
            "convergence_time_seconds": conv_time,
            "change_verified": True,
            "safety_verified": True,
            "connectivity_verified": True if self.connectivity_checker is not None else None,
            "rollback_attempted": False,
            "rollback_success": None,
            "rollback_details": "No rollback required",
            "details": f"Port {bridge}-p{from_port} admin-up verified. Converged in {conv_time}s.",
        }

    def _execute_remove_flow(self, intent, approval_id, verifier_result, incident_context=None):
        sw_id = int(intent.get("target_switch") or intent.get("switch"))
        bridge = f"s{sw_id}"
        cookie = int(str(intent["cookie"]), 0)
        priority = int(str(intent["priority"]))

        # Check ledger before mutation (fail closed if corrupt)
        try:
            ledger_cookies = load_guardrail_cookies(self.ledger_path)
        except CorruptLedgerError as exc:
            return {
                "success": False,
                "action": "remove_flow",
                "error": f"Refusing remove_flow: guardrail ledger is unreadable or corrupt; failing closed: {exc}",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": "Guardrail ledger corruption detected",
            }

        if cookie in ledger_cookies:
            return {
                "success": False,
                "action": "remove_flow",
                "error": f"Refusing remove_flow: cannot delete guardrail-installed rule (cookie 0x{cookie:x} present in guardrail ledger)",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": "Guardrail ledger protection triggered",
            }

        rc, flows_text, err = self._dump_flows(bridge)
        if rc != 0:
            return {
                "success": False,
                "action": "remove_flow",
                "error": f"Unable to dump flows on {bridge} before removal: {err or flows_text}",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": "Pre-execution flow inspection failed",
            }

        target_flow_line = None
        for line in (flows_text or "").splitlines():
            line_str = line.strip()
            flow_cookie = self._flow_cookie(line_str)
            prio_match = re.search(r"\bpriority=(\d+)\b", line_str)
            if flow_cookie == cookie:
                if prio_match and int(prio_match.group(1)) == priority:
                    target_flow_line = line_str
                    break

        if not target_flow_line:
            return {
                "success": False,
                "action": "remove_flow",
                "error": f"Target flow with cookie 0x{cookie:x} and priority {priority} not found on {bridge}",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": "Target flow not found in active OVS flow table",
            }

        # Parse match spec and actions strictly from dumped switch flow
        if "actions=" in target_flow_line:
            match_part, actions_part = target_flow_line.split("actions=", 1)
            dumped_actions = actions_part.strip()
        else:
            match_part, dumped_actions = target_flow_line, "drop"

        prio_m = re.search(r"\bpriority=(\d+)(?:,\s*|\s+|$)(.*)", match_part)
        dumped_match_spec = prio_m.group(2).strip().rstrip(",") if prio_m else ""
        dumped_match_dict = normalize_match_dict(dumped_match_spec)

        # Match must be non-empty and equal to intent match in both directions
        intent_match = intent.get("match", {})
        if not matches_strictly_equal(dumped_match_dict, intent_match):
            return {
                "success": False,
                "action": "remove_flow",
                "error": "Refusing remove_flow: dumped switch match does not strictly match intent match in both directions",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": "Dumped switch flow match does not match intent match",
            }

        # Drift evidence match verification (server-side only)
        if incident_context:
            drift_evidence = (
                incident_context.get("drift_evidence")
                or incident_context.get("anomalous_flows")
                or incident_context.get("evidence", {}).get("flows")
                or []
            )
            evidence_flow = None
            if isinstance(drift_evidence, list):
                for item in drift_evidence:
                    if isinstance(item, dict):
                        item_c = item.get("cookie")
                        item_p = item.get("priority")
                        if item_c is not None and int(str(item_c), 0) == cookie:
                            if item_p is not None and int(str(item_p)) == priority:
                                evidence_flow = item
                                break

            if evidence_flow:
                ev_m = evidence_flow.get("match")
                if not ev_m or not matches_strictly_equal(dumped_match_dict, ev_m):
                    return {
                        "success": False,
                        "action": "remove_flow",
                        "error": "Refusing remove_flow: dumped switch match does not strictly match incident drift evidence in both directions",
                        "change_verified": False,
                        "safety_verified": False,
                        "connectivity_verified": None,
                        "rollback_attempted": False,
                        "rollback_success": None,
                        "rollback_details": "No network mutation was attempted",
                        "details": "Switch match does not match incident drift evidence",
                    }
            else:
                return {
                    "success": False,
                    "action": "remove_flow",
                    "error": "Refusing remove_flow: target flow not found in incident drift evidence with matching cookie and priority",
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": False,
                    "rollback_success": None,
                    "rollback_details": "No network mutation was attempted",
                    "details": "Target flow not in drift evidence",
                }

        # Build del-flows AND inverse strictly from dumped flow
        del_spec = f"cookie=0x{cookie:016x}/0xffffffffffffffff,priority={priority}"
        if dumped_match_spec:
            del_spec += f",{dumped_match_spec}"
        del_cmd = ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "--strict", "del-flows", bridge, del_spec]

        inverse_spec = f"cookie=0x{cookie:016x},priority={priority}"
        if dumped_match_spec:
            inverse_spec += f",{dumped_match_spec}"
        inverse_spec += f",actions={dumped_actions}"
        inverse_cmd = ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "add-flow", bridge, inverse_spec]

        if self.require_human_approval:
            try:
                self.approval_store.consume_approval(
                    approval_id, intent, verifier_result, self.telemetry_path, incident_context=incident_context
                )
            except ApprovalError as exc:
                return {
                    "success": False,
                    "action": "remove_flow",
                    "error": f"Refusing remove_flow: human approval could not be consumed: {exc}",
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": False,
                    "rollback_success": None,
                    "rollback_details": "No network mutation was attempted",
                    "details": "Human approval was revalidated before execution",
                }

        rc, out, err = self.cmd_runner(del_cmd)
        if rc != 0:
            # Failed deletion must NEVER add a new flow!
            return {
                "success": False,
                "action": "remove_flow",
                "target_switch": str(sw_id),
                "cookie": cookie,
                "priority": priority,
                "error": f"OVS del-flows failed on {bridge}: {err or out or 'no details'}",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No rollback attempted: deletion failed before any switch mutation",
                "details": err or out or "OVS del-flows failed",
            }

        # Post-check 1: OVS verification
        rc_v, flows_v, err_v = self._dump_flows(bridge)
        still_present = any(
            self._flow_cookie(l) == cookie and f"priority={priority}" in l
            for l in (flows_v or "").splitlines()
        )
        if rc_v != 0 or still_present:
            rb_rc, rb_out, rb_err = self.cmd_runner(inverse_cmd)
            rollback_ok = (rb_rc == 0)
            return {
                "success": False,
                "action": "remove_flow",
                "target_switch": str(sw_id),
                "cookie": cookie,
                "priority": priority,
                "inverse_command": inverse_cmd,
                "error": f"Post-execution flow verification failed: target flow remains active on {bridge}",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": True,
                "rollback_success": rollback_ok,
                "rollback_details": f"Inverse add-flow executed (rc={rb_rc})",
                "details": "Flow deletion verification failed",
            }

        # Post-check 2: Topology safety
        safety_ok, safety_msg = self._verify_topology_safety()
        if not safety_ok:
            rb_rc, rb_out, rb_err = self.cmd_runner(inverse_cmd)
            rollback_ok = (rb_rc == 0)
            return {
                "success": False,
                "action": "remove_flow",
                "target_switch": str(sw_id),
                "cookie": cookie,
                "priority": priority,
                "inverse_command": inverse_cmd,
                "error": f"Post-execution safety verification failed: {safety_msg}",
                "change_verified": True,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": True,
                "rollback_success": rollback_ok,
                "rollback_details": f"Inverse add-flow executed (rc={rb_rc})",
                "details": f"Flow removed, but topology post-check failed: {safety_msg}",
            }

        # Post-check 3: Live connectivity
        connectivity_verified = None
        if self.connectivity_checker is not None:
            try:
                connectivity_verified = bool(self.connectivity_checker())
            except Exception as exc:
                connectivity_verified = False
                safety_msg += f"; connectivity checker raised: {exc}"

            if not connectivity_verified:
                rb_rc, rb_out, rb_err = self.cmd_runner(inverse_cmd)
                rollback_ok = (rb_rc == 0)
                return {
                    "success": False,
                    "action": "remove_flow",
                    "target_switch": str(sw_id),
                    "cookie": cookie,
                    "priority": priority,
                    "inverse_command": inverse_cmd,
                    "error": f"Post-execution live connectivity check failed. Rollback {'succeeded' if rollback_ok else 'FAILED'}",
                    "change_verified": True,
                    "safety_verified": True,
                    "connectivity_verified": False,
                    "rollback_attempted": True,
                    "rollback_success": rollback_ok,
                    "rollback_details": f"Inverse add-flow executed (rc={rb_rc})",
                    "details": "At least one host-to-host reachability probe failed",
                }

        return {
            "success": True,
            "action": "remove_flow",
            "target_switch": str(sw_id),
            "cookie": cookie,
            "priority": priority,
            "match": dumped_match_spec,
            "inverse_command": inverse_cmd,
            "human_approval_id": approval_id if self.require_human_approval else None,
            "change_verified": True,
            "safety_verified": True,
            "connectivity_verified": connectivity_verified,
            "rollback_attempted": False,
            "rollback_success": None,
            "rollback_details": "No rollback required",
            "details": f"Removed flow cookie=0x{cookie:x} on switch {bridge}. Topology safety: {safety_msg}",
        }

    def _execute_rate_limit_port(self, intent, approval_id, verifier_result, incident_context=None):
        sw_id = int(intent.get("target_switch") or intent.get("switch"))
        from_port = int(intent.get("from_port") or intent.get("port"))
        rate_kbps = int(str(intent["rate_kbps"]))
        bridge = f"s{sw_id}"
        cookie = secrets.randbits(64) or 1

        # Check meter id is free before adding
        rc_m, out_m, _ = self.cmd_runner([
            "sudo", "ovs-ofctl", "-O", "OpenFlow13", "dump-meters", bridge
        ])
        if rc_m == 0:
            meter_pattern = re.compile(rf"\bmeter={re.escape(str(from_port))}\b", re.IGNORECASE)
            if meter_pattern.search(out_m or ""):
                return {
                    "success": False,
                    "action": "rate_limit_port",
                    "target_switch": str(sw_id),
                    "from_port": str(from_port),
                    "rate_kbps": rate_kbps,
                    "error": f"Refusing rate_limit_port: meter ID {from_port} is already in use on {bridge}",
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": False,
                    "rollback_success": None,
                    "rollback_details": "No network mutation was attempted",
                    "details": f"Meter ID {from_port} conflict detected before execution",
                }

        meter_cmd = [
            "sudo", "ovs-ofctl", "-O", "OpenFlow13",
            "add-meter", bridge, f"meter={from_port},kbps,band=type=drop,rate={rate_kbps}",
        ]
        flow_spec = (
            f"cookie=0x{cookie:016x},priority=65000,"
            f"in_port={from_port},actions=meter:{from_port},normal"
        )
        flow_cmd = [
            "sudo", "ovs-ofctl", "-O", "OpenFlow13",
            "add-flow", bridge, flow_spec,
        ]

        del_flow_cmd = [
            "sudo", "ovs-ofctl", "-O", "OpenFlow13",
            "del-flows", bridge, f"cookie=0x{cookie:016x}/0xffffffffffffffff",
        ]
        del_meter_cmd = [
            "sudo", "ovs-ofctl", "-O", "OpenFlow13",
            "del-meter", bridge, f"meter={from_port}",
        ]
        inverse_commands = [del_flow_cmd, del_meter_cmd]

        def resources_absent():
            """Require authoritative OVS dumps to prove this transaction left no resources."""
            rc_flows, flows_text, err_flows = self._dump_flows(bridge)
            if rc_flows != 0:
                return False, f"Unable to verify flow cleanup: {err_flows or flows_text or 'no details'}"
            residual_flows = [
                line.strip() for line in (flows_text or "").splitlines()
                if self._flow_cookie(line) == cookie
            ]
            if residual_flows:
                return False, f"Remediation flow remains after rollback: {residual_flows[0]}"

            rc_meters, meters_text, err_meters = self.cmd_runner([
                "sudo", "ovs-ofctl", "-O", "OpenFlow13", "dump-meters", bridge
            ])
            if rc_meters != 0:
                return False, f"Unable to verify meter cleanup: {err_meters or meters_text or 'no details'}"
            meter_pattern = re.compile(rf"\bmeter={re.escape(str(from_port))}\b", re.IGNORECASE)
            if meter_pattern.search(meters_text or ""):
                return False, f"Meter {from_port} remains on {bridge} after rollback"
            return True, "OVS dumps confirm the transaction flow and meter are absent"

        def release_cookie_after_verification():
            absent, message = resources_absent()
            if not absent:
                return False, message + "; retaining the active ledger reservation"
            try:
                remove_guardrail_cookie(cookie, ledger_path=self.ledger_path)
                return True, message + "; ledger reservation released"
            except Exception as exc:
                return False, message + f"; ledger reservation retained because cleanup failed: {exc}"

        def rollback_rate_limit_resources():
            # Cookie-scoped deletion cannot affect unrelated flows. The meter ID
            # belongs to this transaction after add-meter succeeded.
            self.cmd_runner(del_flow_cmd)
            self.cmd_runner(del_meter_cmd)
            return release_cookie_after_verification()

        if self.require_human_approval:
            try:
                self.approval_store.consume_approval(
                    approval_id, intent, verifier_result, self.telemetry_path, incident_context=incident_context
                )
            except ApprovalError as exc:
                return {
                    "success": False,
                    "action": "rate_limit_port",
                    "error": f"Refusing rate_limit_port: human approval could not be consumed: {exc}",
                    "change_verified": False,
                    "safety_verified": False,
                    "connectivity_verified": None,
                    "rollback_attempted": False,
                    "rollback_success": None,
                    "rollback_details": "No network mutation was attempted",
                    "details": "Human approval was revalidated before execution",
                }

        # Reserve the cookie before the first OVS mutation. If persistence fails,
        # do not create an untracked meter or flow.
        try:
            record_guardrail_cookie(cookie, action="rate_limit_port", bridge=bridge, ledger_path=self.ledger_path)
        except Exception as exc:
            return {
                "success": False, "action": "rate_limit_port",
                "target_switch": str(sw_id), "from_port": str(from_port), "rate_kbps": rate_kbps,
                "error": f"Refusing rate_limit_port: guardrail ledger could not be persisted; failing closed: {exc}",
                "change_verified": False, "safety_verified": False, "connectivity_verified": None,
                "rollback_attempted": False, "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
                "details": "No meter or flow was installed",
            }

        # Step 1: Add meter
        rc1, out1, err1 = self.cmd_runner(meter_cmd)
        if rc1 != 0:
            # A non-zero command result does not prove that OVS made no change.
            # Do not delete a possibly pre-existing meter here; release the cookie
            # only if read-back proves both this flow and the meter are absent.
            ledger_cleanup_ok, cleanup_message = release_cookie_after_verification()
            return {
                "success": False,
                "action": "rate_limit_port",
                "target_switch": str(sw_id),
                "from_port": str(from_port),
                "rate_kbps": rate_kbps,
                "cookie": cookie,
                "inverse_commands": inverse_commands,
                "error": f"OVS add-meter failed on {bridge} meter {from_port}: {err1 or out1 or 'no details'}",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": False,
                "rollback_success": ledger_cleanup_ok,
                "rollback_details": cleanup_message,
                "details": err1 or out1 or "OVS add-meter failed",
            }

        # Step 2: Add flow
        rc2, out2, err2 = self.cmd_runner(flow_cmd)
        if rc2 != 0:
            # The add-flow command may have partially applied despite its error.
            # Remove only our random cookie and our newly-created meter, then
            # release the ledger reservation only after read-back proves absence.
            rb_ok, rb_message = rollback_rate_limit_resources()
            return {
                "success": False,
                "action": "rate_limit_port",
                "target_switch": str(sw_id),
                "from_port": str(from_port),
                "rate_kbps": rate_kbps,
                "cookie": cookie,
                "inverse_commands": inverse_commands,
                "error": (
                    f"OVS add-flow for meter failed on {bridge}: "
                    f"{err2 or out2 or 'no details'}. "
                    f"Rollback {'succeeded' if rb_ok else 'FAILED'}: {rb_message}"
                ),
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": True,
                "rollback_success": rb_ok,
                "rollback_details": rb_message,
                "details": err2 or out2 or "OVS add-flow failed",
            }

        def run_full_rollback():
            rollback_ok, _rollback_message = rollback_rate_limit_resources()
            return rollback_ok

        # Post-check 1: OVS verification
        verified, verify_msg = self._verify_ovs_change(
            bridge, f"in_port={from_port}", f"meter:{from_port}", expected_cookie=cookie
        )
        if not verified:
            rb_ok = run_full_rollback()
            return {
                "success": False,
                "action": "rate_limit_port",
                "target_switch": str(sw_id),
                "from_port": str(from_port),
                "rate_kbps": rate_kbps,
                "cookie": cookie,
                "inverse_commands": inverse_commands,
                "error": f"Post-execution meter flow verification failed on {bridge}: {verify_msg}",
                "change_verified": False,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": True,
                "rollback_success": rb_ok,
                "rollback_details": f"Rollback {'succeeded' if rb_ok else 'FAILED'}",
                "details": verify_msg,
            }

        # Post-check 2: Topology safety
        safety_ok, safety_msg = self._verify_topology_safety()
        if not safety_ok:
            rb_ok = run_full_rollback()
            return {
                "success": False,
                "action": "rate_limit_port",
                "target_switch": str(sw_id),
                "from_port": str(from_port),
                "rate_kbps": rate_kbps,
                "cookie": cookie,
                "inverse_commands": inverse_commands,
                "error": f"Post-execution safety verification failed: {safety_msg}",
                "change_verified": True,
                "safety_verified": False,
                "connectivity_verified": None,
                "rollback_attempted": True,
                "rollback_success": rb_ok,
                "rollback_details": f"Rollback {'succeeded' if rb_ok else 'FAILED'}",
                "details": f"Meter installed, but topology post-check failed: {safety_msg}",
            }

        # Post-check 3: Live connectivity
        connectivity_verified = None
        if self.connectivity_checker is not None:
            try:
                connectivity_verified = bool(self.connectivity_checker())
            except Exception as exc:
                connectivity_verified = False
                safety_msg += f"; connectivity checker raised: {exc}"

            if not connectivity_verified:
                rb_ok = run_full_rollback()
                return {
                    "success": False,
                    "action": "rate_limit_port",
                    "target_switch": str(sw_id),
                    "from_port": str(from_port),
                    "rate_kbps": rate_kbps,
                    "cookie": cookie,
                    "inverse_commands": inverse_commands,
                    "error": f"Post-execution live connectivity check failed. Rollback {'succeeded' if rb_ok else 'FAILED'}",
                    "change_verified": True,
                    "safety_verified": True,
                    "connectivity_verified": False,
                    "rollback_attempted": True,
                    "rollback_success": rb_ok,
                    "rollback_details": f"Rollback {'succeeded' if rb_ok else 'FAILED'}",
                    "details": "At least one host-to-host reachability probe failed",
                }

        return {
            "success": True,
            "action": "rate_limit_port",
            "target_switch": str(sw_id),
            "from_port": str(from_port),
            "rate_kbps": rate_kbps,
            "cookie": cookie,
            "inverse_commands": inverse_commands,
            "human_approval_id": approval_id if self.require_human_approval else None,
            "change_verified": True,
            "safety_verified": True,
            "connectivity_verified": connectivity_verified,
            "rollback_attempted": False,
            "rollback_success": None,
            "rollback_details": "No rollback required",
            "details": f"Rate limit {rate_kbps} kbps installed on {bridge} port {from_port}. Topology safety: {safety_msg}",
        }

    def _dump_ports_desc(self, bridge_name):
        """Read OVS port descriptions using an argument array (no shell expansion)."""
        return self.cmd_runner([
            "sudo", "ovs-ofctl", "-O", "OpenFlow13", "dump-ports-desc", bridge_name
        ])

    @staticmethod
    def _parse_port_config(output, port_num):
        """
        Extract config flags for a specific port from dump-ports-desc output.
        Returns a dict with {"found": bool, "admin_down": bool, "raw": str}.
        """
        if not output:
            return {"found": False, "admin_down": False, "raw": ""}
        port_str = str(port_num)
        pattern = re.compile(rf"^\s*{re.escape(port_str)}\(([^)]+)\):", re.MULTILINE)
        matches = list(pattern.finditer(output))
        if not matches:
            pattern = re.compile(rf"^\s*{re.escape(port_str)}:", re.MULTILINE)
            matches = list(pattern.finditer(output))
        if not matches:
            return {"found": False, "admin_down": False, "raw": ""}

        start_pos = matches[0].start()
        next_match = re.search(r"^\s*\d+[\(:]", output[matches[0].end():], re.MULTILINE)
        if next_match:
            block = output[start_pos : matches[0].end() + next_match.start()]
        else:
            block = output[start_pos:]

        admin_down = False
        for line in block.splitlines():
            line_str = line.strip()
            if line_str.startswith("config:"):
                if "PORT_DOWN" in line_str:
                    admin_down = True
                    break
        return {"found": True, "admin_down": admin_down, "raw": block}

    def _rollback_transaction(self, changes):
        """Roll back every flow added by a transaction, verifying each removal."""
        outcomes = []
        all_ok = True
        for change in reversed(changes):
            ok, message = self._rollback_flow(change["bridge"], change["cookie"])
            if ok:
                try:
                    remove_guardrail_cookie(change["cookie"], ledger_path=self.ledger_path)
                except Exception as exc:
                    ok = False
                    message = f"{message}; ledger cleanup failed: {exc}"
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
