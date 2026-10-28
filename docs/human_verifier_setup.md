# Human Verifier setup

Updated: 2026-10-27

## What it does

A valid `block` proposal is saved as `PENDING_HUMAN_APPROVAL`; it does not change Open vSwitch. The dashboard's **Human Verifier** link opens `/approvals`. An operator must authenticate, review the stored intent/verifier/topology fingerprints, and approve or reject with a reason. Approval expires after five minutes by default, is bound to the exact proposal and current forwarding-relevant topology, and is consumed once.

The executor revalidates the proposal immediately before mutation. It fails closed for missing, rejected, expired, replayed, changed, stale, or unaudited approvals. It also requires a real host-to-host connectivity callback for block operations by default.

## Local setup

From the repository root in WSL, configure a per-operator bearer token in the same terminal used to start the observability server:

```bash
export NETOPS_APPROVER_TOKENS='{"netops-admin":"REPLACE_WITH_A_LONG_RANDOM_SECRET"}'
/home/bennurjeevan/venvs/netops/bin/python observability/server.py
```

Use a strong random secret rather than the placeholder. Keep it private. The server binds to `127.0.0.1:8000` by default. Open:

- Dashboard: `http://127.0.0.1:8000/dashboard`
- Human Verifier: `http://127.0.0.1:8000/approvals`

The approval API is disabled with HTTP 503 when `NETOPS_APPROVER_TOKENS` is unset or invalid. API calls require `Authorization: Bearer <token>`. The token maps to the operator identity configured in the JSON object. A decision without a reason is rejected.

Do not expose this development server directly to an untrusted network. For remote operators, use a properly configured HTTPS reverse proxy, access control, and secret management. Avoid putting bearer tokens in URLs.

## End-to-end usage

1. Start Ryu so that it can produce fresh telemetry in `telemetry/data/latest.json`.
2. Run the decision-gate/remediation-supervisor path as usual. A safe block proposal appears in the approval queue with an expiry and fingerprint; an unsafe proposal is rejected and audited.
3. Open **Human Verifier** from the dashboard and authenticate with the configured operator token.
4. Review the target switch/port, reason, automated verification result, topology and proposal fingerprints, and expiry.
5. Select **Approve proposal**, **Reject proposal**, or **Request changes** and enter an audit reason. A changes-requested proposal is closed; revise the intent and submit a new proposal rather than reusing the old approval.
6. Execution is a separate action after approval. The API refuses to execute unless the matching approval is present in a valid signed audit chain and a connectivity checker is configured.

## Required live connectivity checker

For safety, executing a block additionally requires:

```bash
export NETOPS_CONNECTIVITY_CHECKER='your_project_module:check_host_connectivity'
```

This is a configuration format, not a bundled checker implementation. Replace it only with an importable function that checks reachability of the actual host endpoints in the current testbed and returns the documented success/failure value expected by `RemediationExecutor`. Do not point it at a stub that always returns true. If a trustworthy live checker is unavailable, leave this variable unset: the proposal can be reviewed, but execution remains disabled.

## Freshness and approval lifecycle

- Telemetry must contain `updated_at_utc` and be no older than 30 seconds when a block proposal is created or approved for execution.
- Approval validity includes intent, verifier result, topology, STP state and reported port status. Traffic counters do not invalidate the proposal.
- Pending duplicate proposals with the same fingerprint reuse the existing proposal ID.
- Approve/reject transitions are stored atomically and serialized across processes.
- The executor consumes an approval before issuing network mutations. A consumed or expired approval cannot be replayed.
- A matching signed audit event is required before the execution endpoint proceeds.

## Current limitation

Human approval and fail-closed guards are implemented and unit/API tested. **Automatic active-link failover is still unresolved.** The latest Mininet triangle test did not observe a down/missing port event at Ryu, the alternate remained STP-blocked, and packet loss stayed at 100% until the original link was restored. This failure is recorded in `experiments/results/live_triangle_failover_latest.json`; do not claim automatic failover is working until the live test passes.
