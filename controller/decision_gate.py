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

from safety_verifier import (
    load_telemetry,
    build_topology,
    run_safety_checks,
    test_port_removal
)

from remediation_agent import propose_remediation
from audit_trail import AuditTrail

DEFAULT_TELEMETRY_PATH = os.path.expanduser(
    "~/netops_guardrail/telemetry/data/latest.json"
)

audit_trail = AuditTrail()


def build_graph_from_json(telemetry_path):
    """
    Load telemetry JSON and build the topology graph.
    """

    with open(telemetry_path, "r") as file:
        telemetry = json.load(file)

    return build_topology(telemetry)


def apply_intent_to_graph(graph, intent):

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

        # DECISION GATE REQUIREMENT:
        # Proposed physical port must exist in the topology before simulation
        if port_node not in graph:
            return {
                "safe": False,
                "reason": f"Port {port_node} does not exist"
            }

        return test_port_removal(
            sim_graph,
            port_node
        )

    elif action == "no_action":

        return run_safety_checks(
            sim_graph
        )

    else:

        return {
            "safe": False,
            "reason": (
                f"Unhandled action type: "
                f"{action}"
            )
        }


def decide(
    telemetry_path=None
):
    if telemetry_path is None:
        telemetry_path = DEFAULT_TELEMETRY_PATH

    graph = build_graph_from_json(
        telemetry_path
    )

    intent = propose_remediation(
        telemetry_path
    )

    print("1. AGENT PROPOSED:")
    print(json.dumps(intent, indent=2))

    result = apply_intent_to_graph(
        graph,
        intent
    )

    print("\n2. VERIFIER RESULT:")
    print(json.dumps(result, indent=2))

    decision = (
        "APPROVED"
        if result.get("safe")
        else "REJECTED"
    )

    print(f"\n3. DECISION: {decision}")

    # Minimum integration point: every decision produces a signed audit record
    record = audit_trail.record_decision(
        decision=decision,
        intent=intent,
        verifier_result=result
    )

    print(f"\n4. AUDIT RECORD LOGGED: index={record['index']} hash={record['current_hash'][:16]}...")

    return {
        "intent": intent,
        "verification": result,
        "decision": decision,
        "audit_record": record
    }


if __name__ == "__main__":

    decide()
