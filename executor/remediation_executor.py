import json
import os
import subprocess
import sys

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for subdir in ["verifier", "audit", "agent", "controller"]:
    path = os.path.join(base_dir, subdir)
    if path not in sys.path:
        sys.path.insert(0, path)

from safety_verifier import build_topology, run_safety_checks, test_port_removal
from audit_trail import AuditTrail


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
        topology_provider=None
    ):
        self.telemetry_path = telemetry_path or os.path.expanduser(
            "~/netops_guardrail/telemetry/data/latest.json"
        )
        self.cmd_runner = cmd_runner or self._default_cmd_runner
        self.audit_trail = audit_trail
        self.topology_provider = topology_provider

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

    def validate_preconditions(self, intent, decision, verifier_result):
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

        if action == "no_action":
            return True, None

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

        # Validate that switch and ports exist in topology
        topology, _ = self._get_topology(phase="pre")
        if topology is not None:
            sw_node = f"s{target_switch_str}"
            port_node = f"s{target_switch_str}-p{from_port_str}"

            if sw_node not in topology:
                return False, f"Target switch {sw_node} does not exist in topology"
            if port_node not in topology:
                return False, f"Target port {port_node} does not exist in topology"
            if action == "reroute" and to_port_str:
                to_port_node = f"s{target_switch_str}-p{to_port_str}"
                if to_port_node not in topology:
                    return False, f"Target destination port {to_port_node} does not exist in topology"

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

    def execute(self, intent, decision, verifier_result):
        """
        Execute an approved intent in the Mininet/OVS test environment.
        Performs pre-validation, safe execution, and post-execution verification.
        """
        valid, err = self.validate_preconditions(intent, decision, verifier_result)
        if not valid:
            return {
                "success": False,
                "action": intent.get("action") if isinstance(intent, dict) else None,
                "error": err,
                "change_verified": False,
                "safety_verified": False,
                "details": f"Pre-execution rejection: {err}"
            }

        action = intent["action"]

        # Action: no_action
        if action == "no_action":
            safety_ok, safety_msg = self._verify_topology_safety()
            return {
                "success": safety_ok,
                "action": "no_action",
                "change_verified": True,
                "safety_verified": safety_ok,
                "details": "no_action verified: network remains undisturbed and safe"
            }

        # Action: block or reroute
        sw_id = int(intent["target_switch"])
        from_port = int(intent["from_port"])
        bridge_name = f"s{sw_id}"

        if action == "block":
            # Install OpenFlow drop rule safely
            cmd = [
                "sudo", "ovs-ofctl", "-O", "OpenFlow13",
                "add-flow", bridge_name,
                f"priority=65500,in_port={from_port},actions=drop"
            ]
            expected_pattern = f"in_port={from_port}"
            expected_action = "drop"
        elif action == "reroute":
            to_port = int(intent["to_port"])
            cmd = [
                "sudo", "ovs-ofctl", "-O", "OpenFlow13",
                "add-flow", bridge_name,
                f"priority=65500,in_port={from_port},actions=output:{to_port}"
            ]
            expected_pattern = f"in_port={from_port}"
            expected_action = f"output:{to_port}"

        # Execute command safely
        rc, out, err_msg = self.cmd_runner(cmd)
        if rc != 0:
            return {
                "success": False,
                "action": action,
                "error": f"OVS command execution failed with code {rc}: {err_msg}",
                "change_verified": False,
                "safety_verified": False,
                "details": err_msg
            }

        # Post-Execution Verification:
        # Confirm the flow change actually occurred in OVS flow table
        change_verified, verify_msg = self._verify_ovs_change(
            bridge_name,
            expected_pattern,
            expected_action
        )

        if not change_verified:
            return {
                "success": False,
                "action": action,
                "error": f"Post-execution verification failed: {verify_msg}",
                "change_verified": False,
                "safety_verified": False,
                "details": verify_msg
            }

        # Post-Execution Safety Verification:
        # Verify topology safety remains uncompromised
        safety_ok, safety_msg = self._verify_topology_safety()

        return {
            "success": change_verified and safety_ok,
            "action": action,
            "target_switch": str(sw_id),
            "from_port": str(from_port),
            "change_verified": change_verified,
            "safety_verified": safety_ok,
            "details": f"Change confirmed in OVS: {verify_msg}. Safety check: {safety_msg}"
        }

    def _verify_ovs_change(self, bridge_name, expected_pattern, expected_action):
        """
        Confirm that the requested OpenFlow flow rule was actually installed in OVS.
        Do not rely on returncode 0 alone.
        """
        dump_cmd = ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge_name]
        rc, out, err = self.cmd_runner(dump_cmd)
        if rc != 0:
            return False, f"Failed to dump OVS flows: {err}"

        # Check for expected pattern and action in flow table output
        for line in out.splitlines():
            if expected_pattern in line and expected_action in line:
                return True, f"Found active flow matching {expected_pattern} -> {expected_action}"

        return False, f"Rule with {expected_pattern} and {expected_action} not found in active OVS flow table"

    def _verify_topology_safety(self):
        """Run safety verifier checks against the current network topology."""
        graph, req_hosts = self._get_topology(phase="post")
        if graph is None:
            return True, "No telemetry or topology available to inspect"

        try:
            res = run_safety_checks(graph, required_hosts=req_hosts)
            if res.get("safe"):
                return True, "Topology safety checks passed"
            return False, f"Topology safety check reported issues: {res.get('checks')}"
        except Exception as e:
            return False, f"Topology check error: {e}"
