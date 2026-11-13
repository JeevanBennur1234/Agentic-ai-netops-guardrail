# Phase 1 Presentation Update Notes

> **Current status update — 2026-11-13:** Update slides to reflect five successful 90-second active-trunk failover trials in the Mininet + OVS + Ryu testbed (trials 02, 03, 06, 07, 08). Recovery was 9.042–10.131 seconds; zero post-recovery packet-loss samples were observed. The injected failure was OpenFlow 1.3 administrative port-down, not physical cable unplug. This demonstrates STP failover in the emulated testbed, not an AI agent autonomously performing remediation. The old failover-failed wording later in this note is historical and superseded. Latest local regression: 176 tests passed. See `docs/CLAIMS_EVIDENCE.md`.

Date: 2026-10-27

This note is for updating the slides after the current implementation review. It is not a claim that the supplied PowerPoint has already been edited.

## Slide 8 - Expected Outcomes

Change wording that sounds fully delivered to a status-aware version:
- Working prototype: the core prototype modules are implemented; five 90-second active-trunk failover trials passed in the Mininet + OVS + Ryu emulated testbed.
- Invariant checker: topology-level connectivity/reachability checks, loop reporting/policy and STP-aware forwarding-edge handling are implemented. Do not call it a complete formal OpenFlow verifier.
- Tamper-evident audit: hash/signature audit implementation and audit-chain tests exist.
- Fault injection: synthetic adversarial cases and five repeatable live Mininet/OVS/Ryu active-trunk administrative-down failover trials passed; physical cable-unplug and AI-driven failover remain unverified.
- Comparative evaluation: initial synthetic and component-level measurements exist; no broad manual-vs-autonomous statistical comparison is complete.

## Slide 10 - Current Progress

Suggested status table:

| Task | Updated status | Evidence |
|---|---|---|
| Literature survey | Core sources verified; full bibliography drafted | docs/literature_and_research_gap.md |
| Problem and gap analysis | Narrowed to prototype integration claim | docs/literature_and_research_gap.md |
| Dataset/topology design | Mininet redundant topology and three-switch test topology exist | testbed/redundant_topo.py; testbed/validate_triangle_failover.py |
| System architecture | Agent, verifier, gate, executor, audit and observability modules exist | controller/, agent/, verifier/, executor/, audit/, observability/ |
| Invariant checker | Core graph verifier with STP-aware reachability checks | verifier/safety_verifier.py; tests/test_guardrail.py |
| AI agent | Local Ollama intent proposer with schema and target validation | agent/remediation_agent.py |
| Ryu integration | Telemetry and STP-state integration; decision pipeline and polling supervisor exist | controller/telemetry_controller.py; controller/decision_gate.py; controller/remediation_service.py |
| Fault injection | Synthetic cases and live failure/rollback harnesses exist | experiments/evaluate_guardrail_cases.py; testbed/validate_triangle_failover.py |
| Live active-link failover | Five 90-second trials passed in Mininet + OVS + Ryu; 9.042–10.131 s recovery, zero post-recovery loss samples | experiments/results/2026-11-13_live_active_failover_trial_02/03/06/07/08.json (OpenFlow administrative-down emulation) |

## Slide 7 - Proposed Methodology

Label the AI step "structured intent proposal" rather than implying the model itself formally verifies network changes. The safety verifier is a separate deterministic component.

The "Prometheus/Grafana" item should be described as available observability components unless a fresh end-to-end demo is captured for the presentation.

## Slide 12 - References

Replace the placeholder list of literature topics with the verified references in docs/literature_and_research_gap.md. Use a consistent IEEE-style citation format in the report and cite each surveyed paper in the body.

## Presentation wording to avoid

Avoid:
- "formally proves the whole network is safe"
- "100% accurate"
- "production ready"
- "production-guaranteed or AI-driven active trunk failover"
- "no existing open verifier"

Prefer:
- "topology-level safety gate"
- "Qwen structured-output evaluation: 30/30 valid JSON and schema passes, 0 fallbacks on the defined synthetic set; 2 unsafe mutating proposals blocked by the independent guardrail, 0 passed. This is not general AI accuracy."
- "30/30 simulated executor transactions passed; fake OVS command runner"
- "five 90-second Mininet + OVS + Ryu active-trunk administrative-down failover trials passed; physical cable-unplug and AI-driven failover are not claimed"


## Latest live test result

The dual-trunk active-link failover harness passed five 90-second trials (02, 03, 06, 07, 08) after OpenFlow 1.3 administrative port-down on the primary trunk. The alternate STP path reached FORWARD and host connectivity recovered in 9.042–10.131 seconds, with zero post-recovery loss samples. This is emulated administrative-down evidence, not physical cable-unplug coverage or AI-driven remediation.


## Additional live guardrail evidence

The dual-trunk live integration test now checks an attempted block of the currently forwarding trunk while the alternate trunk is STP-blocked. The gate rejects it, and the executor independently rejects a forged APPROVED verdict; neither attempt adds flow rules and host-to-host connectivity remains intact. This validates safe refusal under the observed topology, not automatic failover.
