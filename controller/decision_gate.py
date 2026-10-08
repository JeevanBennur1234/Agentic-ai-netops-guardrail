import json
import sys
import os

sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "verifier")
)
sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "agent")
)
sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "audit")
)
sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "executor")
)

from safety_verifier import (
    build_topology,
    run_safety_checks,
    test_port_removal
)
from remediation_agent import propose_remediation
from audit_trail import AuditTrail
from remediation_executor import RemediationExecutor

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_LOCAL_TELEMETRY = os.path.join(_PROJECT_ROOT, "telemetry", "data", "latest.json")
_HOME_TELEMETRY = os.path.expanduser("~/netops_guardrail/telemetry/data/latest.json")
DEFAULT_TELEMETRY_PATH = (
    _LOCAL_TELEMETRY if os.path.exists(_LOCAL_TELEMETRY) else _HOME_TELEMETRY
)

audit_trail = AuditTrail()


def build_graph_from_json(telemetry_path):
    """Load telemetry JSON and build the topology graph."""
    with open(telemetry_path, "r") as file:
        telemetry = json.load(file)
    return build_topology(telemetry)


def apply_intent_to_graph(graph, intent):
    """
    Apply a proposed intent against a simulated copy of the topology graph.
    Returns a verifier result dict with at least a 'safe' boolean.
    """
    sim_graph = graph.copy()
    action = intent.get("action")

    if action in ("reroute", "block"):
        target_switch = intent.get("target_switch")
        from_port = intent.get("from_port")

        if not target_switch or not from_port:
            return {
                "safe": False,
                "reason": "Missing target_switch or from_port for remediation action"
            }

        port_node = f"s{target_switch}-p{from_port}"

        # Proposed physical port must exist before simulation
        if port_node not in graph:
            return {
                "safe": False,
                "reason": f"Port {port_node} does not exist"
            }

        return test_port_removal(sim_graph, port_node)

    elif action == "no_action":
        # Baseline topology check — cycles from redundancy are allowed
        return run_safety_checks(sim_graph, require_loop_free=False)

    else:
        return {
            "safe": False,
            "reason": f"Unhandled action type: {action}"
        }


def decide(
    telemetry_path=None,
    execute_approved=True,
    executor=None
):
    if telemetry_path is None:
        telemetry_path = DEFAULT_TELEMETRY_PATH

    graph = build_graph_from_json(telemetry_path)

    try:
        intent = propose_remediation(telemetry_path)
    except Exception as exc:
        intent = {
            "action": "no_action",
            "reason": f"Remediation agent error: {exc}. Defaulted safely to no_action."
        }

    print("1. AGENT PROPOSED:")
    print(json.dumps(intent, indent=2))

    result = apply_intent_to_graph(graph, intent)

    print("\n2. VERIFIER RESULT:")
    print(json.dumps(result, indent=2))

    decision = "APPROVED" if result.get("safe") else "REJECTED"
    print(f"\n3. DECISION: {decision}")

    execution_res = None
    if decision == "APPROVED" and execute_approved:
        if executor is None:
            executor = RemediationExecutor(telemetry_path=telemetry_path)
        execution_res = executor.execute(
            intent=intent,
            decision=decision,
            verifier_result=result
        )
        print("\n4. EXECUTION RESULT:")
        print(json.dumps(execution_res, indent=2))

    # Every decision produces a signed audit record
    record = audit_trail.record_decision(
        decision=decision,
        intent=intent,
        verifier_result=result,
        execution_result=execution_res
    )

    print(
        f"\n5. AUDIT RECORD LOGGED: "
        f"index={record['index']} hash={record['current_hash'][:16]}..."
    )

    return {
        "intent": intent,
        "verification": result,
        "decision": decision,
        "execution": execution_res,
        "audit_record": record
    }


if __name__ == "__main__":
    decide()
