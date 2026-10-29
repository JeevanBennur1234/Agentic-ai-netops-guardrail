# Live Demo Runbook - Agentic AI-NetOps Guardrail
Date: 2026-10-28

## Promise and safety boundary
This demo covers the web dashboard, live Mininet/OVS telemetry, a verifier-approved proposal in the Human Verifier queue, a safe standby-trunk remediation test, automated tests, and synthetic evaluation results.

Do not claim active-link failover works. The latest interface-down experiment failed to reconverge. Do not run that failure injection as a live success demo.

## 0. Pre-flight
Use WSL Ubuntu-22.04. Project root: /home/bennurjeevan/netops_guardrail

~~~bash
cd /home/bennurjeevan/netops_guardrail
test -x /home/bennurjeevan/venvs/netops/bin/python && echo "Python venv OK"
sudo ovs-vsctl list-br
ss -ltnp | grep 6653
~~~

If any s1/s2/s3 OVS bridge already exists, do not start another Mininet topology or a validator. Identify the owner first. Do not use broad cleanup commands if another lab could be running.

## 1. Terminal A - Ryu
First check:
~~~bash
pgrep -af ryu-manager
ss -ltnp | grep 6653
~~~
If port 6653 is already listening for this project, leave it running; do not launch a duplicate. Otherwise:
~~~bash
cd /home/bennurjeevan/netops_guardrail
sudo -E /home/bennurjeevan/venvs/netops/bin/ryu-manager --ofp-tcp-listen-port 6653 controller/telemetry_controller.py
~~~
Leave Terminal A open and wait for successful startup.

## 2. Terminal B - Web dashboard and Human Verifier
Run the checked-in local startup helper:
~~~bash
cd /home/bennurjeevan/netops_guardrail
chmod +x start_local_observability.sh
./start_local_observability.sh
~~~
The helper configures both `NETOPS_APPROVER_TOKENS` and `NETOPS_CHAOS_API_TOKEN`, plus the real connectivity checker required by the issue endpoints. It creates reusable random local tokens outside the repository in `~/.config/netops-guardrail/local-secrets.env` (directory mode 700, file mode 600) and prints them for this local session. Keep Terminal B open; if port 8000 is already occupied, identify the existing process instead of starting a duplicate.
The server binds to localhost port 8000. Do not expose this development server to untrusted networks.

Open in the Windows browser:
- Dashboard: http://127.0.0.1:8000/dashboard
- Human Verifier: http://127.0.0.1:8000/approvals

Copy the token from Terminal B into the Human Verifier page. Never put it in slides or screenshots. Health checks:
~~~bash
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/api/status
~~~
If port 8000 is busy, inspect the existing process rather than starting a duplicate.

## 3. Terminal C - Keep Mininet live for the UI
First confirm there are no pre-existing s1/s2 bridges:
~~~bash
sudo ovs-vsctl list-br
~~~
If clear, start the two-switch dual-trunk topology:
~~~bash
cd /home/bennurjeevan/netops_guardrail
sudo mn --custom /home/bennurjeevan/netops_guardrail/testbed/redundant_topo.py --topo redundant --controller=remote,ip=127.0.0.1,port=6653 --switch ovs,protocols=OpenFlow13
~~~
Leave Terminal C at the mininet> prompt. Do not run another Mininet test while these bridges exist.

At mininet>:
~~~text
nodes
net
links
pingall
~~~
Wait about 10-15 seconds for STP/LLDP telemetry before interpreting the first ping. Expected steady state: 0% packet loss, one redundant trunk blocked by STP, and host access ports forwarding. While it remains live, refresh the browser dashboard and show the discovered topology.

## 4. Terminal D - Create a review-only Human Verifier item
With Mininet still running and Ryu telemetry fresh:
~~~bash
cd /home/bennurjeevan/netops_guardrail
/home/bennurjeevan/venvs/netops/bin/python testbed/create_demo_approval.py
~~~
The helper checks telemetry freshness (maximum 30 seconds), both discovered trunks, access-port forwarding, a STP-blocked trunk endpoint, and the existing automated verifier. It creates a pending Human Verifier proposal and signed audit entry. It never calls the executor or modifies OVS flows.

Open /approvals, click Refresh, authenticate if prompted, and show the proposal intent, verifier result, topology/proposal fingerprints, and expiry. For the safest demo choose Request changes or Reject proposal and enter an audit reason. If you choose Approve proposal, stop at the approved state; do not click Execute approved action unless a genuine environment-specific connectivity checker has been configured.

If helper says telemetry is stale or links are missing, do not alter timestamps manually. Keep Mininet running, wait for Ryu link discovery and telemetry refresh, then retry once.

## 5. Exit the interactive topology cleanly
At mininet>, type:
~~~text
exit
~~~
Wait for Mininet to stop, then check:
~~~bash
sudo ovs-vsctl list-br
~~~
Do not proceed to the live remediation validator if test bridges remain or another topology is active.

## 6. Demonstrate the live safe-remediation integration test
Run sequentially, never simultaneously:
~~~bash
cd /home/bennurjeevan/netops_guardrail
sudo -E /usr/bin/python3 testbed/validate_redundant_topology.py
sudo -E /usr/bin/python3 testbed/validate_trunk_remediation.py
~~~
These scripts verify Ryu availability and refuse to touch pre-existing s1/s2 bridges. The remediation test exercises a cookie-scoped block on the already STP-blocked standby trunk, validates both rule installs, checks live connectivity, rejects unsafe active-trunk/access-port requests, and verifies a temporary audit chain. Expected result is PASS with 0% packet loss. This is a live testbed integration, not proof of physical active-link failover or execution through the web approval endpoint.

If a validator reports existing bridges, stop and identify the owner; do not run broad OVS cleanup blindly.

## 7. Run regression tests and evaluation
~~~bash
cd /home/bennurjeevan/netops_guardrail
/home/bennurjeevan/venvs/netops/bin/pytest -q
/home/bennurjeevan/venvs/netops/bin/python experiments/evaluate_guardrail_cases.py
cat experiments/results/recommended_evaluation_20261027.md
~~~
Latest verified baseline: 155 tests passed. The evaluation uses 12 manually labelled synthetic cases and 30 executor transactions using an in-memory fake OVS runner. The 30 transactions are not 30 live OVS changes; reported latency is simulated software-path timing, not data-plane latency.

To show the known limitation without injecting another live failure:
~~~bash
cat experiments/results/link_down_diagnostic_20261027.md
~~~

## Recommended 8-12 minute presentation
1. Problem and architecture - 1 minute.
2. Live dashboard/topology and pingall - 2 minutes.
3. Human Verifier queue and decision - 2 minutes.
4. Standby-trunk remediation test and safety rejections - 3 minutes.
5. Automated tests/evaluation report - 1 minute.
6. State active-link failover limitation and next experiment - 1 minute.

Suggested wording:
"The AI proposes a network action but does not directly control the network. The automated verifier checks it against the observed forwarding topology. A human can approve, reject, or request changes. The executor has independent safety checks and needs a genuine connectivity checker before live block execution. We tested safe standby-trunk remediation and unsafe-action rejection in Mininet, and 155 automated tests currently pass. Active-link failover after the tested interface-down event is still unresolved, so we are not claiming that it works."

## If something fails
- Ryu not listening: start it in Terminal A and wait for startup.
- Dashboard has no topology: confirm mininet> is still running; wait for LLDP/STP telemetry, then refresh.
- Proposal helper reports stale telemetry: keep the topology live and wait for Ryu to refresh telemetry; do not edit timestamps.
- OVS bridge conflict: stop and identify its owner. Do not run topology scripts in parallel.
- Execute action disabled: expected without a real lab-specific connectivity checker. Do not use a stub that always returns true.
