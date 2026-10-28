# Phase 1 Presentation Update Notes
Date: 2026-10-27

This note is for updating the slides after the current implementation review. It is not a claim that the supplied PowerPoint has already been edited.

## Slide 8 - Expected Outcomes

Change wording that sounds fully delivered to a status-aware version:
- Working prototype: the core prototype modules are implemented; live active-trunk failover remains unresolved.
- Invariant checker: topology-level connectivity/reachability checks, loop reporting/policy and STP-aware forwarding-edge handling are implemented. Do not call it a complete formal OpenFlow verifier.
- Tamper-evident audit: hash/signature audit implementation and audit-chain tests exist.
- Fault injection: synthetic adversarial cases and live Mininet experiments exist; current active-trunk failure test fails over unsuccessfully but confirms rollback recovery.
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
| Live active-link failover | Not passed; rollback recovery passed | experiments/results/live_triangle_failover_latest.json |

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
- "successful active trunk failover"
- "no existing open verifier"

Prefer:
- "topology-level safety gate"
- "12 manually labelled synthetic cases passed; this does not measure LLM accuracy"
- "30/30 simulated executor transactions passed; fake OVS command runner"
- "active failover not demonstrated; rollback restored connectivity"


## Latest live test result

The two-switch topology/host-connectivity test and the paired trunk-rule safety test passed. The active-trunk administrative-down experiment on a three-switch ring did not fail over: host ping loss rose to 100% with the alternate trunk still STP-blocked. Restoring the original trunk returned ping loss to 0%. This was not a physical cable-unplug test. Show this as an unresolved result and do not list active failover as completed.


## Additional live guardrail evidence

The dual-trunk live integration test now checks an attempted block of the currently forwarding trunk while the alternate trunk is STP-blocked. The gate rejects it, and the executor independently rejects a forged APPROVED verdict; neither attempt adds flow rules and host-to-host connectivity remains intact. This validates safe refusal under the observed topology, not automatic failover.
