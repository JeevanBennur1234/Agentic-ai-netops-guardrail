#!/usr/bin/env python3
"""Create a review-only Human Verifier item from fresh live telemetry. Never executes an action."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from netops_guardrail.netops_paths import NETOPS_HOME

ROOT = NETOPS_HOME

from netops_guardrail.audit.audit_trail import AuditTrail
from netops_guardrail.controller.decision_gate import apply_intent_to_graph
from netops_guardrail.controller.human_verifier import (
    ApprovalError,
    HumanApprovalStore,
    topology_fingerprint_from_path,
)
from netops_guardrail.verifier.safety_verifier import build_topology

TELEMETRY_PATH = ROOT / "telemetry" / "data" / "latest.json"
TRACE_PATH = ROOT / "observability" / "data" / "pipeline_trace.jsonl"


def link_key(link):
    left = f"s{str(link.get('src_switch', '')).strip()}-p{str(link.get('src_port', '')).strip()}"
    right = f"s{str(link.get('dst_switch', '')).strip()}-p{str(link.get('dst_port', '')).strip()}"
    return tuple(sorted((left, right)))


def append_pipeline_trace(intent, verification, proposal, audit_record, trace_path=None):
    """Mirror this review-only proposal into the live dashboard trace stream."""
    destination = Path(trace_path) if trace_path is not None else TRACE_PATH
    destination.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "intent": intent,
        "verification": verification,
        "decision": "PENDING_HUMAN_APPROVAL",
        "execution": None,
        "human_approval": {
            "proposal_id": proposal["proposal_id"],
            "status": proposal["status"],
            "proposal_fingerprint": proposal["proposal_fingerprint"],
            "expires_at": proposal["expires_at"],
        },
        "audit_record": audit_record,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, default=str) + "\n")


def select_standby_s1_port(telemetry):
    expected = {
        tuple(sorted(("s1-p2", "s2-p1"))),
        tuple(sorted(("s1-p3", "s2-p2"))),
    }
    observed = {link_key(link) for link in telemetry.get("links", []) if isinstance(link, dict)}
    if not expected.issubset(observed):
        raise ApprovalError("Both redundant trunks are not discovered. Keep Mininet running and wait for Ryu link discovery.")
    switches = telemetry.get("switches", {})
    states = {
        str(sw): {str(port): str(state).upper() for port, state in (data.get("stp_port_states") or {}).items()}
        for sw, data in switches.items() if isinstance(data, dict)
    }
    if states.get("1", {}).get("1") != "FORWARD" or states.get("2", {}).get("3") != "FORWARD":
        raise ApprovalError("Both host access ports must be FORWARD; refusing demo proposal.")
    for link in telemetry.get("links", []):
        if not isinstance(link, dict):
            continue
        src_sw, src_port = str(link.get("src_switch", "")), str(link.get("src_port", ""))
        dst_sw, dst_port = str(link.get("dst_switch", "")), str(link.get("dst_port", ""))
        if src_sw == "1" and dst_sw == "2":
            s1_port, peer_state = src_port, states.get("2", {}).get(dst_port, "UNKNOWN")
        elif src_sw == "2" and dst_sw == "1":
            s1_port, peer_state = dst_port, states.get("2", {}).get(src_port, "UNKNOWN")
        else:
            continue
        s1_state = states.get("1", {}).get(s1_port, "UNKNOWN")
        if s1_port in {"2", "3"} and (s1_state == "BLOCK" or peer_state == "BLOCK"):
            return s1_port
    raise ApprovalError("No inter-switch trunk has a STP BLOCK endpoint; refusing demo proposal.")


def main():
    try:
        telemetry = json.loads(TELEMETRY_PATH.read_text(encoding="utf-8"))
        topology_fingerprint_from_path(TELEMETRY_PATH)  # rejects stale telemetry
        selected_port = select_standby_s1_port(telemetry)
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": selected_port,
            "reason": "Presentation demo: review the already STP-blocked redundant trunk; this helper never executes it.",
        }
        verification = apply_intent_to_graph(build_topology(telemetry), intent)
        if verification.get("safe") is not True:
            raise ApprovalError("Automated verifier did not approve this proposal: " + str(verification.get("reason", verification)))
        proposal = HumanApprovalStore().create_proposal(
            intent=intent, verifier_result=verification,
            telemetry_path=str(TELEMETRY_PATH), requested_by="presentation-demo",
        )
        audit_record = AuditTrail().record_decision(
            decision="PENDING_HUMAN_APPROVAL",
            intent=intent,
            verifier_result=verification,
            execution_result={"human_approval": {
                "proposal_id": proposal["proposal_id"],
                "status": proposal["status"],
                "proposal_fingerprint": proposal["proposal_fingerprint"],
                "expires_at": proposal["expires_at"],
            }, "demo_only": True, "network_mutation_attempted": False},
        )
        try:
            append_pipeline_trace(intent, verification, proposal, audit_record)
        except OSError as exc:
            print(f"WARNING: approval is saved, but dashboard trace update failed: {exc}", file=sys.stderr)
        print(json.dumps({
            "result": "PENDING_HUMAN_APPROVAL",
            "proposal_id": proposal["proposal_id"],
            "expires_at": proposal["expires_at"],
            "intent": intent,
            "automated_verification": verification,
            "network_mutation_attempted": False,
            "next_step": "Open http://127.0.0.1:8000/approvals and review this proposal.",
        }, indent=2, default=str))
        return 0
    except (OSError, json.JSONDecodeError, ApprovalError, ValueError) as exc:
        print(f"DEMO PROPOSAL NOT CREATED: {exc}", file=sys.stderr)
        print("No OVS flow changes were attempted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
