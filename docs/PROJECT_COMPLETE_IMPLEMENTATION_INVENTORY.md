# Agentic AI-NetOps Guardrail — Complete Project Implementation Inventory

> Before running these examples, set NETOPS_HOME to the repository root and activate the Python environment: export NETOPS_HOME="$(pwd)" followed by source "$NETOPS_HOME/.venv/bin/activate".


**Prepared:** 28 October 2026
**Repository:** https://github.com/JeevanBennur1234/Agentic-ai-netops-guardrail
**Branch reviewed:** master
**Latest code commit at preparation:** 16ad240 — Add guarded remediation workflow and readable Human Verifier UI
**Environment:** WSL Ubuntu 22.04 on Windows
**Project root:** $NETOPS_HOME

> This inventory describes implemented code, recorded test evidence, live experiments, and known limitations. It distinguishes real live-test results from synthetic or simulated results and does not claim production readiness.

## Contents

1. Summary and project goals
2. Technology and topology
3. End-to-end architecture
4. Every major component
5. AI proposal and safety-gate behavior
6. Human Verifier and approval lifecycle
7. Executor, post-checks, rollback, audit
8. Dashboard, API and issue workflows
9. Security controls
10. Test suite inventory
11. Evaluation results
12. Live lab results and limitations
13. Repository file inventory
14. Development milestones
15. Setup and operations commands
16. Guide/viva explanation
17. Claims that are safe to make
18. Final checklist
19. Full existing project documents as appendices

## 1. Summary and project goals

Agentic AI-NetOps Guardrail is a research prototype for safer AI-assisted network remediation in a software-defined network (SDN). It integrates a local language-model intent proposer, Ryu network telemetry, a NetworkX topology safety verifier, a decision gate, an authenticated Human Verifier, a constrained Open vSwitch executor, post-change checks, scoped rollback attempts, and a signed/hash-linked audit trail.

The governing principle is:

**AI proposes → independent code verifies → human authorizes → constrained executor acts → post-checks and audit record the result.**

The repository also includes an interactive topology dashboard, two issue-specific proposal workflows, a readable Human Verifier UI, Prometheus metrics endpoints/configuration, experiment and benchmark tools, live Mininet/OVS validation scripts, research notes, a system design/threat model, presentation guidance, and a demo runbook.

### Current status snapshot

- The latest recorded full pytest run on 28 October 2026 passed 169 tests, with one upstream eventlet/distutils deprecation warning.
- Twelve manually labelled synthetic safety cases matched the expected safety labels. This is evidence for that small deterministic test set, not a measurement of general LLM accuracy.
- Thirty simulated executor transactions passed using an in-memory fake OVS command runner. No real OVS commands or live connectivity tests were run by that benchmark.
- The recorded two-switch redundant-topology baseline passed with 0% ping loss.
- A live standby-trunk rule test checked paired rules and continued connectivity, and rejected selected unsafe access-port/active-trunk requests.
- Automatic active-link failover is not working/verified in the current live failure experiment. The alternate link remained STP-blocked, packet loss rose to 100%, and connectivity recovered only after the original link was restored.
- Production readiness is not established.

### Project goals

1. Collect current network state from a Ryu/Mininet/Open vSwitch environment.
2. Give a local model sanitized telemetry and valid physical-port information.
3. Ask the model for a structured remediation intent instead of a shell command.
4. Validate schema, action, switch and port.
5. Check graph connectivity, endpoint reachability, loop policy, and the effect of a proposed port removal.
6. Reject unsafe, malformed, unsupported, stale, or unaudited operations.
7. Route eligible safe block actions to human review instead of executing immediately.
8. Bind approval to the exact intent, verifier result, and topology fingerprint.
9. Enforce expiry, a human reason, authentication and one-time approval consumption.
10. Revalidate again immediately before execution.
11. Use constrained cookie-tagged flow rules, post-verification, and a real connectivity callback where required.
12. Attempt rollback when an execution postcondition fails.
13. Record decisions and outcomes in the signed/hash-linked audit trail.
14. Provide a dashboard, trace/metrics APIs, repeatable tests, experiment output, and documentation.

### Correct contribution statement

The defensible contribution is the integration of an LLM intent proposer, a topology-aware safety gate, a constrained executor, human authorization, audit, and Mininet-based evaluation. This project does not claim equivalence to formal verifiers such as Header Space Analysis, VeriFlow, or NetKAT.

## 2. Technologies and topology

### Technologies

| Technology | Role |
|---|---|
| Python | Agent, verifier, gate, executor, approval store, audit, server, tests and experiments. |
| WSL Ubuntu 22.04 | Local development and test environment. |
| Mininet | Emulates hosts, links, and switches. |
| Open vSwitch | Virtual switches and OpenFlow rules. |
| OpenFlow 1.3 | Controller/switch protocol. |
| Ryu | SDN controller and telemetry event source. |
| LLDP/link discovery | Discovers links between switches. |
| STP | Prevents Layer-2 loops by blocking redundant paths. |
| Ollama | Runs a local LLM. |
| qwen2.5-coder:1.5b | Model referenced by project notes as the local default; runtime model selection is configurable. |
| NetworkX | Graph-based topology invariants. |
| Flask-style HTTP server | Dashboard, Human Verifier, API, metrics and trace. |
| Prometheus/Grafana assets | Monitoring configuration, metrics and dashboard/schema support. |
| pytest | Automated test suite. |
| Git/GitHub | Source control and remote repository. |

### Local paths and URLs

- Project root: $NETOPS_HOME
- Python interpreter: $VIRTUAL_ENV/bin/python
- Dashboard: http://127.0.0.1:8000/dashboard
- Human Verifier: http://127.0.0.1:8000/approvals
- Health: http://127.0.0.1:8000/health
- Ryu/OpenFlow listener: 127.0.0.1:6653
- Git remote: https://github.com/JeevanBennur1234/Agentic-ai-netops-guardrail.git

### Main topology

The main network is created by testbed/redundant_topo.py. It has hosts h1 and h2, switches s1 and s2, and two inter-switch trunks:

- Primary trunk: s1-p2 ↔ s2-p1.
- Standby trunk: s1-p3 ↔ s2-p2.
- Host-facing ports include s1-p1 and s2-p3.

A typical healthy state has the primary trunk and host access ports forwarding, with at least one standby endpoint blocked by STP. For example, s1-p3=FORWARD and s2-p2=BLOCK is normal redundancy behavior, not an anomaly by itself.

A three-switch/ring topology is used by dedicated failover and diagnostic scripts; it is not assumed to run simultaneously with the standard two-switch topology.

## 3. End-to-end architecture

1. Ryu polls OpenFlow port/flow statistics and receives switch, link-discovery, STP and port-status events.
2. The telemetry controller writes a timestamped JSON snapshot using a temporary file and atomic replacement.
3. The agent sanitizes telemetry and asks the local model for structured intent JSON.
4. Schema checks and telemetry-derived target checks reject malformed output or invalid ports.
5. The NetworkX verifier builds a graph and checks connectivity, reachability, loop policy, and simulated port removal.
6. The decision gate rejects an unsafe proposal or records an eligible safe block proposal as PENDING_HUMAN_APPROVAL.
7. The authenticated Human Verifier shows the proposal and records approve, reject, or request-changes plus an audit reason.
8. Execution is separate. The execution endpoint verifies that the approval exists in the audit chain and checks the proposal/topology again.
9. The constrained executor applies the permitted change using cookie-tagged flow rules at both ends of a selected trunk.
10. Flow, topology, and configured connectivity postconditions are checked.
11. If a required postcondition fails, scoped rollback is attempted and its result is recorded.
12. The audit trail, pipeline trace, metrics and dashboards provide evidence.

### Separate concepts

- Automated verifier safe result means only that the configured automated checks passed.
- PENDING_HUMAN_APPROVAL means a proposal is waiting for the operator.
- Approved means the operator authorized the exact proposal; the change may not have run yet.
- Execution success must be established from the executor result and relevant post-checks.

A passing verifier status is not human approval and is not proof that the network changed.

## 4. Every major component

### agent/remediation_agent.py

- Uses a local Ollama inference endpoint.
- Sanitizes telemetry and provides valid physical-port information.
- Requests structured JSON intent against a declared schema.
- Validates required fields, action names and target details.
- Validates physical ports against telemetry.
- Does not convert model prose into executable shell commands.
- Defaults safely, such as to no_action, when model output is invalid or the service fails.
- Supports incident-specific context, including honest Issue 2 controlled-simulation labeling.

agent/remediation_agent_gemini.py is also present as an additional agent-related module; the architecture notes identify remediation_agent.py/Ollama as the primary path.

### verifier/safety_verifier.py

- Loads telemetry and builds a graph from switches, ports, links and available status.
- Excludes local/reserved OpenFlow ports from valid physical targets.
- Builds a forwarding graph that respects STP and reported port state.
- When STP telemetry exists, a physical inter-switch link is not considered an available forwarding path unless both relevant endpoints report FORWARD.
- Checks topology existence, connectivity, loop policy, access-endpoint reachability and simulated port-removal effects.
- Handles incomplete state conservatively where it affects safety.
- Returns structured check results/reasons.

This is topology-level graph analysis, not complete symbolic verification of arbitrary OpenFlow matches/actions, packet headers, VLAN policy, middleboxes, or every network behavior.

### controller/decision_gate.py

- Integrates agent proposals and deterministic verification.
- Simulates action effects against the topology graph.
- Rejects invalid and unsafe actions.
- Routes eligible safe block actions into PENDING_HUMAN_APPROVAL without changing OVS at proposal time.
- Revalidates approved proposals before execution.
- Adds decision evidence to audit and pipeline trace.
- Fails closed for unsupported reroute and unsafe trunk/access-port actions.
- Includes regression work around loop-free defaults and require_loop_free behavior.

### controller/telemetry_controller.py

- Ryu application for OpenFlow 1.3.
- Handles switch features and datapath events.
- Requests/processes flow and port statistics.
- Discovers links and updates topology.
- Records STP state transitions and OpenFlow port-status events when reported.
- Publishes a timestamped snapshot using temporary-file writing and atomic replacement.
- Uses a project-local snapshot path so sudo/root execution does not cause the reader and writer to use different files.

Atomic replacement prevents partial JSON reads but does not make observations from multiple switches globally simultaneous. In the recorded link-down tests, an interface-down event did not produce the needed OpenFlow DOWN/MISSING signal, so correcting the telemetry path alone did not fix failover.

### controller/human_verifier.py

- Stores intent, verifier result, requester, status, creation/expiry, fingerprints and decision.
- Computes topology and exact proposal fingerprints.
- Defaults to a 300-second/five-minute approval lifetime.
- Rejects missing or unsafe verifier results.
- Deduplicates identical unexpired pending proposals by fingerprint.
- Uses a process lock and atomic file update.
- Requires an authenticated approver, a matching fingerprint, and a non-empty decision reason.
- Supports approve, reject and request-changes.
- Refuses expired or non-pending decisions.
- Revalidates intent/verifier/topology before execution and consumes approval once.

### controller/remediation_service.py

- Watches telemetry file content fingerprints.
- Runs the decision pipeline when the snapshot changes.
- Defaults to dry-run.
- Execute mode requires an explicit module:function connectivity checker.
- Reports invalid checker configuration or failed executor results.
- Is a manually launched component, not an installed persistent OS service.

### executor/remediation_executor.py

- Independently validates actions, targets and stored human approval.
- Rejects malformed/nonexistent targets, reserved/local ports, access-port blocks and unsupported operations.
- Restricts live block operations to eligible inter-switch trunks.
- Does not accept a caller-supplied APPROVED string as sufficient authorization.
- Requires a live connectivity checker by default for block execution.
- Uses argument-array subprocess calls rather than shell command concatenation.
- Adds cookie/transaction-tagged drop rules at both ends of a selected trunk.
- Checks for conflicts with existing flow rules.
- Verifies installed flow entries and topology safety.
- Runs live connectivity post-checks when configured/required.
- Attempts scoped rollback and reports rollback failure honestly.

Reroute remains rejected until forwarding-aware verification exists.

### audit/audit_trail.py

- Canonically serializes audit payloads.
- Maintains previous-hash-linked records.
- Signs records using ECDSA-based signing material.
- Persists and reloads the chain.
- Verifies hashes, signatures and chain links.
- Has tests for altered intent, decision, verifier result, timestamps, signature, hash links, deleted intermediate records, corrupt key behavior and file permissions.

This is application-level tamper-evident evidence, not independent hardware attestation.

### observability/server.py and observability/metrics.py

- Serve health/status, dashboard, Human Verifier, topology, trace, audit chain and metrics.
- Protect proposal-trigger actions with configured operator tokens.
- Require an approver-token map for approval APIs.
- Append human decision trace events so later human actions are visible separately from the original AI proposal.
- Prevent execution if approval/audit/connectivity prerequisites are missing or invalid.
- Implement Issue 1 and Issue 2 endpoints.

### dashboard/index.html

- Interactive topology graph and live refresh.
- Pipeline trace with decision/check/reason/time.
- Audit/observability sections.
- Link to Human Verifier.
- Issue 1 Inject Fault → AI Proposal button.
- Issue 2 Standby Forwarding button.
- Protected operator token prompt.
- Error and proposal-created messages.
- Lifecycle-aware status tint: pending is amber; approved-but-not-executed is blue; a safety pass is green only when no stronger active lifecycle state overrides it, or execution success is confirmed.

This was changed because “VERIFIER: SAFE” looked like human approval even while the actual proposal was still pending.

### Human Verifier UI

The raw JSON is no longer the primary presentation. Proposal cards provide:
- Issue details in plain language.
- Changes to address the issue.
- Automated safety checks with individual results.
- Your Decision with required reason and Approve/Reject/Request changes.
- Collapsible technical details for fingerprints, timestamps, target data and original reason.
- Separate approved-but-not-executed state and separate Execute approved action button.
- Rejected, changes-requested and consumed states with clear wording.
- A warning not to claim success until execution and connectivity checks confirm it.

### Other modules

- testbed/live_connectivity.py: checks actual host-to-host reachability in the current Mininet lab and fails closed if a host is missing.
- observability/prometheus.yml: Prometheus scrape configuration.
- experiments/experiment_suite.py: structured experiment suite.
- experiments/runner.py: runs suite and creates report output.
- experiments/benchmark.py: component benchmark utility.
- experiments/topologies.py: synthetic topology builders.
- experiments/evaluate_guardrail_cases.py: newer manually labelled safety cases and fake-runner executor benchmark.
- dashboard/index.html: user-facing topology/pipeline view.
- testbed/: topology, demo approval, diagnostics and live validation scripts.
- tests/: automated regression coverage.

## 5. AI proposal and safety-gate behavior

The agent receives sanitized telemetry, links/ports, STP evidence and relevant incident context. It outputs an intent such as no_action or block. Although reroute appears in the action vocabulary, it is intentionally rejected downstream until safe forwarding-aware verification exists.

Validation includes:
- Structured schema validation.
- Supported action checking.
- Physical-port and switch target validation against current telemetry.
- Rejection of local/reserved OpenFlow ports and fabricated targets.
- Safe fallback when the model output or model service fails.
- Independent graph verification rather than trusting the model’s claimed safety.

The deterministic verifier checks topology existence, connectivity, loop policy, endpoint reachability, and effects of a candidate port removal. A link being physically discovered does not automatically mean it is forwarding: STP and reported port status matter.

## 6. Human approval and execution

Approval configuration:
- NETOPS_APPROVER_TOKENS: JSON mapping operator IDs to long random tokens.
- NETOPS_CHAOS_API_TOKEN: token for protected proposal-trigger endpoints.
- NETOPS_CONNECTIVITY_CHECKER: environment-specific module:function for live connectivity checks.

Approval behavior:
- Five-minute expiry by default.
- A decision reason is mandatory.
- Fingerprint must match the exact stored proposal.
- Stale or changed topology is rejected.
- Duplicate unexpired pending proposals can reuse an existing ID.
- Approval is used once and cannot be replayed.
- A matching audit record is required before execution.
- Execution rechecks proposal, topology and the live checker.
- Approval is separate from execution.

Keep tokens out of source control, screenshots, chat, URLs and slides. The local development server should not be exposed to untrusted networks.

## 7. Executor, post-checks, rollback and audit

A block action is restricted to an eligible inter-switch trunk with an alternate topology path. The executor installs cookie-tagged drop rules at both ends. It checks expected rules, checks topology safety, and requires a live connectivity checker by default. A successful OVS command alone is not proof that hosts can still communicate.

If a required postcondition fails, the executor attempts to remove only rules associated with its own transaction and reports whether rollback was verified. The audit trail records decisions and results using a hash-linked, signed record sequence.

## 8. Issue 1 — controlled redundant-trunk workflow

Issue 1 is the Inject Fault → AI Proposal demonstration path. It is not a real primary-link failure injector and does not deliberately create a broadcast loop in the current implementation.

The recorded behavior:
- Checks topology and live connectivity.
- Ensures/restores the standby path/interfaces for the controlled scenario.
- Reconciles pre-existing guardrail drop rules on standby ports where necessary.
- Verifies link/port/telemetry conditions.
- Runs the AI and safety gate.
- Can propose blocking switch 1, port 3 (s1-p3) to isolate the standby trunk for review.
- Creates PENDING_HUMAN_APPROVAL rather than executing at proposal time.

Describe it as controlled standby-trunk proposal/review workflow—not proof of a real loop or primary-path failure.

## 9. Issue 2 — standby-forwarding detection

The detector is in controller/standby_anomaly.py and the protected route is /api/chaos/standby-forwarding?confirm=true.

A real anomaly requires:
- Telemetry no older than 30 seconds.
- Both trunks and expected ports discovered.
- Both primary endpoints FORWARD.
- Both host-facing ports FORWARD.
- Both standby endpoints simultaneously FORWARD.

A normal state with one standby endpoint STP-blocked is not an anomaly.

When the real condition is absent, an explicitly chosen controlled simulation can demonstrate review workflow without mutating OVS/STP or fabricating telemetry. It is labelled controlled_simulation, and the AI reason says the signal is simulated. It can create a review-only proposal, not automatically execute it.

Tests cover healthy state, both-end forwarding detection, stale telemetry, missing link, no proposal without anomaly/simulation, and safe simulation semantics. During the latest observed lab check, s1-p3 was FORWARD while s2-p2 was BLOCK, so the live dual-forwarding anomaly was absent.

## 10. Security controls

| Risk | Control | Remaining work |
|---|---|---|
| Invalid or hallucinated intent | Schema and target validation, safe fallback. | More adversarial model-output evaluation. |
| Fabricated switch/port | Telemetry-derived target validation. | Coherent multi-switch snapshot remains a challenge. |
| Access-port outage | Gate and executor reject access-port block. | Broader VLAN/host cases. |
| Unsafe reroute | Fail-closed rejection. | Implement forwarding-aware verification first. |
| Shell injection | Intent is not a command; use argument arrays/shell=False. | Preserve in all extensions. |
| Stale telemetry | Timestamp freshness check. | Snapshot is not globally atomic across switches. |
| Changed topology after approval | Fingerprints and fresh validation. | More concurrency/race testing. |
| Forged/replayed approval | Authenticated stored approval, audit binding and one-time consume. | Continue regression testing. |
| Partial rule installation | Paired rules and scoped rollback. | More one-sided failure injection. |
| Connectivity loss | Live callback and postcondition with rollback attempt. | Active failover still unresolved. |
| Audit alteration | Signed/hash-linked chain. | Operational key custody/rotation/backup. |
| Secret exposure | Environment tokens and ignored local runtime/keys. | Rotate if a secret is exposed. |

## 11. Test suite inventory

There are 13 current pytest test modules; parameterized tests make the number of executed test cases larger than literal test-function count.

| Test module | Main coverage |
|---|---|
| tests/test_adversarial.py | Missing/malformed fields, unsupported actions, invalid targets, reserved port, injection-shaped target, access-port isolation, unsafe block. |
| tests/test_agent_incident_context.py | Sanitization, structured proposal context, Issue 2 simulation labeling. |
| tests/test_audit_trail.py | Chain creation/persistence, signature/hash tamper, broken links, deleted entry, corrupt key, permissions. |
| tests/test_demo_approval.py | Demo candidate selection, verifier pass, trace record. |
| tests/test_experiments.py | Experiment suite, topologies, benchmark stats, normal/unsafe/adversarial/audit/observability behavior. |
| tests/test_guardrail.py | Target validation, schema, topology/loop/reachability, STP-aware paths, port-status down. |
| tests/test_human_verifier.py | Fingerprints, expiry, single-use, reason, topology tamper, request changes, forged approval, connectivity prerequisite. |
| tests/test_live_connectivity.py | Bidirectional host connectivity and missing-host failure. |
| tests/test_observability.py | Health/metrics/dashboard, read-only invariant, auth, approvals, execution, trace, Issue 1/2 and readable UI. |
| tests/test_recommended_evaluation.py | Synthetic safety metrics and fake-OVS transaction benchmark. |
| tests/test_remediation_executor.py | Allowed/refused execution, invalid target, bypass attempts, post-check, rollback and failure reporting. |
| tests/test_remediation_service.py | Dry-run, telemetry fingerprints, callable loader, execute prerequisite, failures. |
| tests/test_standby_anomaly.py | Healthy STP, actual dual-forwarding, stale telemetry and missing-link behavior. |

Latest full run: **169 passed, 1 warning**. The warning is an upstream eventlet/distutils deprecation. Passing tests are not a substitute for live network tests.

## 12. Evaluation results

### Synthetic labelled safety cases

- 12 manually labelled cases: 3 safe, 9 unsafe.
- 12/12 matched their expected labels.
- 0 false accepts among the 9 unsafe cases.
- 0 false rejects among the 3 safe cases.

These figures are only for this small deterministic fixture set; they do not demonstrate the language model is 100% accurate.

### Simulated executor transactions

- 30 requested, 30 passed, 0 failed.
- Mean 0.277 ms; median 0.221 ms; p95 0.380 ms; min 0.212 ms; max 1.279 ms.
- Used in-memory fake OVS command runner.
- Did not execute actual OVS commands or test live connectivity.

These are simulated software-path timings, not live data-plane latency.

## 13. Live testbed results

### Redundant topology baseline — PASS

The recorded two-switch topology converged with one standby endpoint blocked and host access ports forwarding. Baseline ping loss was 0%.

### Paired standby-trunk rules — PASS

The recorded test installed and verified cookie-tagged drop rules at both ends of the standby trunk; post-test connectivity reported 0% loss. An access-port block was rejected without changing checked rules. The gate and executor also refused a block of the active trunk when the alternate was STP-blocked; those refusals did not change the checked flow rules and host connectivity remained intact. A temporary audit chain verified.

This demonstrates bounded standby-rule execution and safe refusal; it does not demonstrate active-link failover.

### Active-link failover — FAILOVER_FAILED_ROLLBACK_PASS

The recorded failure experiments started with 0% loss, then emulated an active-path failure. Ryu did not report the needed OpenFlow DOWN/MISSING event, the alternate trunk remained STP-blocked, and loss reached 100% during the failover window. Restoring the original trunk returned connectivity to 0% loss.

The injected event used Mininet/Linux interface-down or configLinkStatus-style behavior, not a confirmed physical cable unplug. Correcting the telemetry path and making STP-priority setup deterministic did not make the latest failover test pass. Automatic active-link failover is therefore unresolved and must not be described as working.

## 14. Repository file inventory

### Agent
- agent/remediation_agent.py — Ollama intent proposer, sanitizer, schema/target validation.
- agent/remediation_agent_gemini.py — additional agent-related module.

### Controller and safety
- controller/telemetry_controller.py — telemetry collection.
- controller/decision_gate.py — safety gate and pipeline.
- controller/human_verifier.py — approval store and lifecycle.
- controller/remediation_service.py — snapshot watcher/supervisor.
- controller/standby_anomaly.py — Issue 2 detector.
- verifier/safety_verifier.py — NetworkX safety checks.
- executor/remediation_executor.py — constrained changes, checks, rollback.

### Audit, UI and observability
- audit/audit_trail.py — signed/hash-linked log.
- observability/server.py — UI and APIs.
- observability/metrics.py — metrics.
- observability/prometheus.yml — Prometheus settings.
- dashboard/index.html — topology dashboard and issue controls.

### Testbed
- testbed/redundant_topo.py — main topology.
- testbed/live_connectivity.py — real connectivity checker.
- testbed/create_demo_approval.py — review-only proposal helper.
- testbed/diagnose_link_down.py — link-down diagnostics.
- testbed/validate_redundant_topology.py — baseline test.
- testbed/validate_trunk_remediation.py — two-ended rule/post-check test.
- testbed/validate_active_failover.py — active failure validation.
- testbed/validate_triangle_failover.py — ring failover/rollback test.

### Experiments
- experiments/experiment_suite.py — structured scenarios.
- experiments/runner.py — runs and reports experiments.
- experiments/benchmark.py — component/transaction benchmarks.
- experiments/topologies.py — synthetic topologies.
- experiments/evaluate_guardrail_cases.py — current synthetic safety and fake-runner transaction evaluation.
- experiments/results/recommended_evaluation_20261027.json and .md — evaluation results.
- experiments/results/live_integration_summary_20261027.json — live integration summary.
- experiments/results/live_active_failover_latest.json — active failure record.
- experiments/results/live_triangle_failover_latest.json — ring failure record.
- experiments/results/link_down_diagnostic_20261027.md — link-down diagnosis.

### Tests and existing docs
- 13 tests files are listed in Section 11.
- Existing docs: architecture overview, Human Verifier setup, dated implementation status, Issue 2, literature/research gap, live demo runbook, presentation update notes, and system design/threat model.

Runtime snapshots, audit runtime data, signing keys, Python caches, and runtime logs are not source features. The latest pushed project version removed six experiment private-key files from the Git index and ignores generated runtime logs/caches. Never commit tokens or private key values.

## 15. Development milestone history

| Commit | Recorded message |
|---|---|
| 0908443 | Milestone 3: controlled remediation execution with OVS post-verification and audit extension. |
| decca31 | Milestone 4: Prometheus observability and Grafana configuration. |
| 01ddc25 | Milestone 5: experiments and performance benchmarking. |
| 2d31646 | Milestone 6: live topology discovery and evaluation rigor. |
| fc24314 | Interactive dashboard, live topology testbed and benchmarks. |
| fa58a40 | Harden agent schema validation and normalize missing reason. |
| f8a9500 | Safety-verifier fixes for redundant topology, reachability and path fallback. |
| 4651c53 | Fail-closed loop policy, trace logging, dashboard API and live UI. |
| 2132653 | Loop-policy override regression fix, dashboard Phase 1–3, regression tests. |
| 16ad240 | Guarded remediation workflow and readable Human Verifier UI. |

The last pre-inventory push was verified with local HEAD equal to origin/master at 16ad240 and a clean working tree. This inventory will be a new documentation commit.

## 16. Setup and operation commands

### Preflight

    cd "$NETOPS_HOME"
    test -x $VIRTUAL_ENV/bin/python && echo "Python venv OK"
    pgrep -af '[r]yu-manager' || true
    pgrep -af '[o]bservability/server.py' || true
    sudo ovs-vsctl list-br
    ss -ltnp | grep -E '6653|8000' || true

Do not start duplicate Ryu, server, or Mininet if it is already running.

### Start Ryu if stopped

    cd "$NETOPS_HOME"
    sudo -E $VIRTUAL_ENV/bin/ryu-manager --ofp-tcp-listen-port 6653 controller/telemetry_controller.py

### Configure tokens and start the local server

Use strong, different secrets and keep them private.

    cd "$NETOPS_HOME"
    export NETOPS_CHAOS_API_TOKEN="REPLACE_WITH_LONG_RANDOM_OPERATOR_TOKEN"
    export NETOPS_APPROVER_TOKENS='{"netops-admin":"REPLACE_WITH_DIFFERENT_LONG_RANDOM_APPROVER_TOKEN"}'
    export NETOPS_CONNECTIVITY_CHECKER='testbed.live_connectivity:check_host_connectivity'
    $VIRTUAL_ENV/bin/python observability/server.py

If health already returns OK, keep the existing server instead of starting a duplicate. The development server should remain local unless proper remote access controls and HTTPS are configured.

### Start the Mininet lab only when no conflicting bridges exist

    sudo ovs-vsctl list-br
    cd "$NETOPS_HOME"
    sudo mn --custom $NETOPS_HOME/testbed/redundant_topo.py --topo redundant --controller=remote,ip=127.0.0.1,port=6653 --switch ovs,protocols=OpenFlow13

At mininet>, run nodes, net, links, pingall. Allow STP and LLDP telemetry to settle.

### Verify health, connectivity and telemetry

    curl -fsS http://127.0.0.1:8000/health
    sudo ovs-vsctl list-br
    $VIRTUAL_ENV/bin/python -m testbed.live_connectivity

    $VIRTUAL_ENV/bin/python - <<'PY'
    import json
    with open("telemetry/data/latest.json", encoding="utf-8") as f:
        data = json.load(f)
    print("Updated:", data.get("updated_at_utc"))
    print("Links:", data.get("links", []))
    for switch, details in data.get("switches", {}).items():
        print("Switch", switch, details.get("stp_port_states", {}))
    PY

### Run tests and synthetic evaluation

    $VIRTUAL_ENV/bin/python -m pytest -q
    $VIRTUAL_ENV/bin/python experiments/evaluate_guardrail_cases.py
    cat experiments/results/recommended_evaluation_20261027.md

### Inspect flow rules

    sudo ovs-ofctl -O OpenFlow13 dump-flows s1
    sudo ovs-ofctl -O OpenFlow13 dump-flows s2
    sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep 'priority=65500' || true
    sudo ovs-ofctl -O OpenFlow13 dump-flows s2 | grep 'priority=65500' || true

Do not remove flows blindly. Confirm their owner and transaction first.

## 17. Suggested demonstration and viva explanation

### Safe demo sequence

1. Preflight controller, server, OVS bridges and Mininet.
2. Confirm pingall and the live connectivity callback.
3. Show discovered topology and STP state.
4. Trigger Issue 1 or Issue 2 proposal workflow.
5. If Issue 2 is controlled simulation, say explicitly that the real anomaly was absent.
6. Show Issue details, Changes to address the issue, Automated safety checks, and Your Decision in Human Verifier.
7. Explain that a pending proposal is not executed.
8. For a safe review demonstration, reject or request changes with a reason. Execute only when a real checker and lab impact are understood.
9. Show audit and trace record.
10. In a separate isolated run, use the validated standby-trunk test and show the post-check.
11. Show test/evaluation output and label the synthetic/fake-runner evidence correctly.
12. Explain the unresolved failover result honestly.

### Simple explanation to a guide

My project is Agentic AI-NetOps Guardrail. It uses a local AI model to suggest network fixes, but it does not let the AI change the network directly. Ryu collects information from the Mininet and Open vSwitch lab. The model proposes a structured action, and a separate graph-based safety verifier checks the topology, connectivity, reachability and configured loop policy.

If a block proposal passes the automated checks, it goes to the Human Verifier and waits for an authorized operator. The operator can approve, reject, or request changes and must give a reason. The approval is tied to the exact proposal and current topology and can be used only once. The executor revalidates the approval, applies a limited trunk-block action, verifies the flow rules and live connectivity, and attempts rollback if a required check fails. The audit trail records the decisions and outcomes.

I have implemented the two proposal workflows, dashboard, readable Human Verifier, automated tests, synthetic evaluation and live testbed scripts. The two-switch baseline and standby-trunk rule test passed in the recorded environment. Automatic active-link failover after the tested failure remains unresolved, so I do not claim it works.

**Memorable line:** The AI proposes, the verifier checks, the human authorizes, the executor applies, and post-checks/audit record the result.

## 18. Safe claims and claims to avoid

### Safe to claim
- A local AI intent proposer is integrated with a separate topology-aware safety gate.
- The graph verifier checks a limited set of topology and reachability invariants with STP-aware forwarding.
- Human approval is authenticated, reasoned, expiring, fingerprint-bound and single-use.
- Executor actions are constrained, cookie-tagged and checked after mutation, with rollback attempts.
- Audit records are signed/hash-linked and tamper tests exist.
- The current Human Verifier has readable summaries and technical details.
- Issue 2 has a live telemetry detector plus a labelled controlled-simulation path.
- The most recent full test suite passed 169 tests.
- Standby-trunk integration passed in the recorded live test.
- The active-link failover experiment did not pass, while restoring the original path recovered connectivity.

### Do not claim
- Production readiness.
- Formal proof of the whole network.
- General 100% AI accuracy from 12 synthetic cases.
- Real OVS/data-plane latency from the fake-runner benchmark.
- Safe verifier result equals human approval or successful execution.
- A real Issue 2 anomaly when the mode is controlled_simulation.
- Successful automatic active-link failover.
- Physical cable-unplug coverage from the recorded emulated/admin-down test.
- That no other network verifiers exist.

## 19. Final checklist

### Implemented
- [x] Local AI structured intent proposal.
- [x] Telemetry sanitation and physical-port validation.
- [x] Ryu/OpenFlow statistics, link discovery, STP/port-status telemetry.
- [x] Timestamped atomic telemetry snapshot.
- [x] NetworkX topology/forwarding checks.
- [x] Decision gate and fail-closed rejection.
- [x] Pending human-approval lifecycle.
- [x] Authentication, decision reason, fingerprints, expiry and one-time consumption.
- [x] Separate approved execute endpoint.
- [x] Cookie-tagged two-ended trunk rules and post-check.
- [x] Scoped rollback attempts.
- [x] Live connectivity checker integration.
- [x] Signed/hash-linked audit.
- [x] Dashboard, metrics, topology, trace and approval APIs.
- [x] Issue 1 controlled proposal workflow.
- [x] Issue 2 detector and controlled simulation.
- [x] Human Verifier readability changes and regression test.
- [x] Testbed, experiments, documentation and automated test coverage.

### Tested in recorded environment
- [x] Full pytest run: 169 passed, one deprecation warning.
- [x] Human Verifier JavaScript syntax check.
- [x] Redundant topology baseline.
- [x] Standby-trunk paired rule and post-check.
- [x] Unsafe active-trunk/access-port refusal.
- [x] Audit-chain verification in live integration test.
- [x] 12/12 synthetic labelled cases.
- [x] 30/30 fake-OVS benchmark transactions.

### Still open/not proven
- [ ] Reliable active-link failure detection and alternate-path convergence.
- [ ] Successful live automatic active-link failover.
- [ ] Physical cable-unplug test.
- [ ] Broader independently labelled LLM quality evaluation.
- [ ] Safe forwarding-aware reroute verification.
- [ ] More partial-install and rollback-failure injections.
- [ ] Production operational hardening, key lifecycle, remote HTTPS deployment, persistent supervisor.

## 20. Full reference documents

The full reference documents are maintained as standalone source files in this directory. Refer to each document below:

- **[Appendix A — Full architecture overview](architecture_overview.md)**: End-to-end component interactions, telemetry pipeline, and decision verification flow.
- **[Appendix B — Human Verifier setup and lifecycle](human_verifier_setup.md)**: Single-use approval token generation, cryptographic validation, and operator decision lifecycle.
- **[Appendix C — Implementation status and evidence](implementation_status.md)**: Detailed milestone verification records, test counts, and benchmark findings.
- **[Appendix D — Issue 2 standby-forwarding details](issue2_standby_forwarding.md)**: Standby link forwarding anomaly detection, containment workflows, and evaluation cases.
- **[Appendix E — Literature survey and research gap](literature_and_research_gap.md)**: Comparative analysis against existing LLM-assisted network automation and formal verification frameworks.
- **[Appendix F — Live demo runbook](live_demo_runbook.md)**: Step-by-step procedures for live Mininet testbed execution, chaos injection, and human approval walkthrough.
- **[Appendix G — Presentation update notes](phase1_presentation_update_notes.md)**: Project review slides, milestone achievements, and architecture evolution notes.
- **[Appendix H — System design and threat model](system_design_and_threat_model.md)**: Adversarial threat model, fail-closed security invariants, and attack vector mitigations.
