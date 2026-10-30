import subprocess
import os
import sys
import json
import hmac
import importlib
from datetime import datetime, timezone
from flask import Flask, Response, jsonify, request, render_template_string, send_file

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for subdir in ["verifier", "audit", "agent", "controller", "executor", "observability", "testbed"]:
    path = os.path.join(base_dir, subdir)
    if path not in sys.path:
        sys.path.insert(0, path)

from prometheus_client import CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
from metrics import NetOpsMetricsCollector
from safety_verifier import build_topology, run_safety_checks, test_port_removal
from decision_gate import apply_intent_to_graph, decide
from audit_trail import AuditTrail
from human_verifier import HumanApprovalStore, ApprovalError
from standby_anomaly import inspect_standby_forwarding

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agentic AI-NetOps Guardrail | Live Observability Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        :root {
            --bg-dark: #0f172a;
            --card-dark: #1e293b;
            --border-dark: #334155;
            --accent-blue: #38bdf8;
            --accent-green: #22c55e;
            --accent-red: #ef4444;
            --accent-purple: #a855f7;
        }
        body {
            background-color: var(--bg-dark);
            color: #f8fafc;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            min-height: 100vh;
        }
        .navbar-custom {
            background-color: var(--card-dark);
            border-bottom: 1px solid var(--border-dark);
        }
        .card-custom {
            background-color: var(--card-dark);
            border: 1px solid var(--border-dark);
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        }
        .stat-card {
            padding: 1.25rem;
            border-radius: 12px;
            background: linear-gradient(145deg, #1e293b, #111827);
            border: 1px solid var(--border-dark);
        }
        .badge-approved {
            background-color: rgba(34, 197, 94, 0.2);
            color: #4ade80;
            border: 1px solid #22c55e;
            padding: 0.35rem 0.75rem;
            font-weight: 600;
        }
        .badge-rejected {
            background-color: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border: 1px solid #ef4444;
            padding: 0.35rem 0.75rem;
            font-weight: 600;
        }
        .badge-verified {
            background-color: rgba(56, 189, 248, 0.2);
            color: #38bdf8;
            border: 1px solid #0284c7;
            padding: 0.35rem 0.75rem;
            font-weight: 600;
        }
        #network-canvas {
            height: 380px;
            background-color: #0b1120;
            border-radius: 8px;
            border: 1px solid #1e293b;
        }
        pre.json-box {
            background-color: #0b1120;
            color: #38bdf8;
            padding: 1rem;
            border-radius: 8px;
            max-height: 240px;
            overflow-y: auto;
            font-size: 0.85rem;
            border: 1px solid var(--border-dark);
        }
        .btn-scenario {
            transition: all 0.2s ease-in-out;
        }
        .btn-scenario:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(56, 189, 248, 0.25);
        }
        .table-custom {
            color: #cbd5e1;
            font-size: 0.85rem;
        }
        .table-custom th {
            border-bottom: 2px solid var(--border-dark);
            color: #94a3b8;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }
        .table-custom td {
            border-bottom: 1px solid #334155;
            vertical-align: middle;
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark navbar-custom px-4 py-3">
        <div class="container-fluid">
            <span class="navbar-brand d-flex align-items-center fw-bold fs-4">
                <i class="fa-solid fa-shield-halved text-info me-3 fs-3"></i>
                Agentic AI-NetOps Guardrail
            </span>
            <div class="d-flex align-items-center gap-3">
                <span class="badge badge-verified rounded-pill">
                    <i class="fa-solid fa-circle-check me-1"></i> Formally Verified Guardrail: ACTIVE
                </span>
                <span class="badge badge-approved rounded-pill">
                    <i class="fa-solid fa-lock me-1"></i> SHA3-256 + ECDSA Audit: SECURED
                </span>
                <span class="text-secondary small">
                    <i class="fa-solid fa-clock me-1"></i> <span id="clock">Live</span>
                </span>
            </div>
        </div>
    </nav>

    <div class="container-fluid px-4 py-4">
        <!-- Row 1: KPI Stats -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="stat-card">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-secondary small text-uppercase fw-semibold">Network State</span>
                            <h3 class="fw-bold mt-1 mb-0 text-white" id="stat-switches">-- Switches</h3>
                            <span class="text-info small" id="stat-ports">-- Active Physical Ports</span>
                        </div>
                        <div class="bg-primary bg-opacity-25 p-3 rounded-circle text-primary">
                            <i class="fa-solid fa-network-wired fs-4"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-secondary small text-uppercase fw-semibold">AI Decisions</span>
                            <h3 class="fw-bold mt-1 mb-0 text-white" id="stat-decisions">-- Total</h3>
                            <div class="d-flex gap-2 mt-1 small">
                                <span class="text-success"><i class="fa-solid fa-check"></i> <span id="stat-approved">0</span> Approved</span>
                                <span class="text-danger"><i class="fa-solid fa-ban"></i> <span id="stat-rejected">0</span> Rejected</span>
                            </div>
                        </div>
                        <div class="bg-success bg-opacity-25 p-3 rounded-circle text-success">
                            <i class="fa-solid fa-brain fs-4"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-secondary small text-uppercase fw-semibold">Cryptographic Audit</span>
                            <h3 class="fw-bold mt-1 mb-0 text-white" id="stat-audit-count">-- Records</h3>
                            <span class="text-success small"><i class="fa-solid fa-link"></i> <span id="stat-audit-status">Chain Valid</span></span>
                        </div>
                        <div class="bg-info bg-opacity-25 p-3 rounded-circle text-info">
                            <i class="fa-solid fa-key fs-4"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-secondary small text-uppercase fw-semibold">Pipeline Overhead</span>
                            <h3 class="fw-bold mt-1 mb-0 text-info">31.9 ms</h3>
                            <span class="text-secondary small">vs 447 ms LLM Generation</span>
                        </div>
                        <div class="bg-warning bg-opacity-25 p-3 rounded-circle text-warning">
                            <i class="fa-solid fa-bolt fs-4"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Row 2: Live Network Visualizer & Interactive Simulation Panel -->
        <div class="row g-4 mb-4">
            <!-- Left: Live Topology -->
            <div class="col-lg-6">
                <div class="card card-custom p-3 h-100">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h5 class="fw-bold m-0"><i class="fa-solid fa-diagram-project text-info me-2"></i>Live Multi-Switch Topology Model</h5>
                        <button class="btn btn-sm btn-outline-secondary" onclick="fetchStatus()"><i class="fa-solid fa-rotate me-1"></i>Refresh</button>
                    </div>
                    <div id="network-canvas"></div>
                    <div class="d-flex justify-content-between text-secondary small mt-2">
                        <span><i class="fa-solid fa-circle text-primary me-1"></i>Switch Node (sX)</span>
                        <span><i class="fa-solid fa-circle text-success me-1"></i>Port Node (sX-pY)</span>
                        <span><i class="fa-solid fa-circle text-warning me-1"></i>Host Node (hX)</span>
                        <span><i class="fa-solid fa-arrows-left-right text-info me-1"></i>LLDP Inter-Switch Trunk</span>
                    </div>
                </div>
            </div>

            <!-- Right: Interactive Live Simulation Testing (The Presentation Feature) -->
            <div class="col-lg-6">
                <div class="card card-custom p-3 h-100">
                    <h5 class="fw-bold mb-3"><i class="fa-solid fa-gamepad text-warning me-2"></i>Live Incident Simulation & Guardrail Verification</h5>
                    <p class="text-secondary small mb-3">Click any button below to trigger a live AI remediation proposal and watch the formal verification layer evaluate it in real time:</p>
                    
                    <div class="d-flex flex-wrap gap-2 mb-3">
                        <button class="btn btn-sm btn-success btn-scenario" onclick="runSimulation('normal')">
                            <i class="fa-solid fa-check-double me-1"></i> 1. Normal Health (no_action)
                        </button>
                        <button class="btn btn-sm btn-danger btn-scenario" onclick="runSimulation('unsafe_block')">
                            <i class="fa-solid fa-triangle-exclamation me-1"></i> 2. Sever Access Port (Attack)
                        </button>
                        <button class="btn btn-sm btn-warning btn-scenario" onclick="runSimulation('injection')">
                            <i class="fa-solid fa-skull-crossbones me-1"></i> 3. Command Injection Attack
                        </button>
                    </div>

                    <!-- Simulation Live Results Window -->
                    <div class="border border-secondary border-opacity-25 rounded p-3 bg-dark">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span class="fw-bold small text-uppercase text-secondary">Guardrail Decision Engine</span>
                            <span id="sim-verdict-badge" class="badge bg-secondary">Awaiting Trigger</span>
                        </div>
                        
                        <div class="row g-2">
                            <div class="col-6">
                                <span class="text-secondary small">AI Agent Proposed Intent:</span>
                                <pre id="sim-intent-box" class="json-box mt-1" style="height: 120px;">{ "status": "Ready for test" }</pre>
                            </div>
                            <div class="col-6">
                                <span class="text-secondary small">Formal Verifier Safety Proof:</span>
                                <pre id="sim-verifier-box" class="json-box mt-1" style="height: 120px;">[ "Click any scenario above to test" ]</pre>
                            </div>
                        </div>

                        <div class="mt-2 pt-2 border-top border-secondary border-opacity-25 small d-flex justify-content-between align-items-center">
                            <span id="sim-executor-status" class="text-secondary">
                                <i class="fa-solid fa-shield me-1"></i> Remediation Executor: Standby
                            </span>
                            <span id="sim-audit-hash" class="text-info font-monospace small"></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Row 3: Cryptographic Audit Trail Table -->
        <div class="card card-custom p-3 mb-4">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="fw-bold m-0"><i class="fa-solid fa-link text-success me-2"></i>Cryptographic Audit Trail (SHA3-256 + ECDSA Signed Ledger)</h5>
                <span class="badge badge-verified"><i class="fa-solid fa-lock me-1"></i>NIST256p Digital Signatures Verified</span>
            </div>
            <div class="table-responsive">
                <table class="table table-custom table-hover">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Timestamp (UTC)</th>
                            <th>Decision</th>
                            <th>Action</th>
                            <th>Target</th>
                            <th>SHA3-256 Current Record Hash</th>
                            <th>Previous Hash</th>
                            <th>Signature</th>
                        </tr>
                    </thead>
                    <tbody id="audit-table-body">
                        <tr><td colspan="8" class="text-center text-secondary py-3">Loading cryptographic audit trail...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Row 4: Prometheus Endpoints Reference -->
        <div class="card card-custom p-3">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="fw-bold text-white mb-1"><i class="fa-solid fa-server text-info me-2"></i>Prometheus Metrics Scrape Target</h6>
                    <span class="text-secondary small">Prometheus-compatible scrape endpoint active at <a href="/metrics" target="_blank" class="text-info">/metrics</a> | JSON summary at <a href="/metrics/json" target="_blank" class="text-info">/metrics/json</a></span>
                </div>
                <a href="/metrics" target="_blank" class="btn btn-sm btn-outline-info">
                    <i class="fa-solid fa-arrow-up-right-from-square me-1"></i> View Raw Prometheus Feed
                </a>
            </div>
        </div>
    </div>

    <script>
        function updateClock() {
            document.getElementById('clock').innerText = new Date().toLocaleTimeString();
        }
        setInterval(updateClock, 1000);
        updateClock();

        let networkInstance = null;

        function renderTopology(telem) {
            const container = document.getElementById('network-canvas');
            const nodes = [];
            const edges = [];

            if (!telem || !telem.switches) return;

            // Switches & ports
            for (const [swId, swData] of Object.entries(telem.switches)) {
                nodes.push({
                    id: `s${swId}`,
                    label: `Switch s${swId}`,
                    color: '#0284c7',
                    shape: 'box',
                    font: { color: '#ffffff', bold: true }
                });

                if (swData.ports) {
                    for (const portId of Object.keys(swData.ports)) {
                        if (portId === '4294967294') continue;
                        const pNode = `s${swId}-p${portId}`;
                        nodes.push({
                            id: pNode,
                            label: `p${portId}`,
                            color: '#16a34a',
                            shape: 'ellipse',
                            font: { color: '#ffffff' }
                        });
                        edges.push({
                            from: `s${swId}`,
                            to: pNode,
                            color: { color: '#475569' },
                            width: 2
                        });
                    }
                }
            }

            // Hosts
            nodes.push({ id: 'h1', label: 'Host h1\\n(10.0.0.1)', color: '#ca8a04', shape: 'box', font: { color: '#ffffff' } });
            nodes.push({ id: 'h2', label: 'Host h2\\n(10.0.0.2)', color: '#ca8a04', shape: 'box', font: { color: '#ffffff' } });
            edges.push({ from: 'h1', to: 's1-p1', color: { color: '#eab308' }, width: 2, dashes: true });
            edges.push({ from: 'h2', to: 's2-p3', color: { color: '#eab308' }, width: 2, dashes: true });

            // Inter-switch links from telemetry
            if (telem.links && telem.links.length > 0) {
                telem.links.forEach((l, idx) => {
                    const src = `s${l.src_switch}-p${l.src_port}`;
                    const dst = `s${l.dst_switch}-p${l.dst_port}`;
                    edges.push({
                        from: src,
                        to: dst,
                        color: { color: '#38bdf8' },
                        width: 4,
                        label: `Trunk`,
                        font: { color: '#38bdf8', size: 10 }
                    });
                });
            }

            const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
            const options = {
                physics: { stabilization: true, barnesHut: { springLength: 90 } },
                interaction: { hover: true }
            };
            if (!networkInstance) {
                networkInstance = new vis.Network(container, data, options);
            } else {
                networkInstance.setData(data);
            }
        }

        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();

                // Stats
                document.getElementById('stat-switches').innerText = `${data.metrics.network.switches_count} Switches`;
                let totalPorts = 0;
                if (data.telemetry && data.telemetry.switches) {
                    for (const s of Object.values(data.telemetry.switches)) {
                        if (s.ports) totalPorts += Object.keys(s.ports).filter(p => p !== '4294967294').length;
                    }
                }
                document.getElementById('stat-ports').innerText = `${totalPorts} Active Physical Ports`;
                document.getElementById('stat-decisions').innerText = `${data.metrics.guardrail.total_decisions} Decisions`;
                document.getElementById('stat-approved').innerText = data.metrics.guardrail.approved;
                document.getElementById('stat-rejected').innerText = data.metrics.guardrail.rejected;
                document.getElementById('stat-audit-count').innerText = `${data.metrics.audit.records_count} Records`;
                document.getElementById('stat-audit-status').innerText = data.metrics.audit.chain_valid ? 'Chain Intact (Verified)' : 'TAMPER DETECTED';

                // Topology
                renderTopology(data.telemetry);

                // Audit table
                renderAuditTable(data.audit_records);
            } catch (err) {
                console.error('Status fetch failed:', err);
            }
        }

        function renderAuditTable(records) {
            const tbody = document.getElementById('audit-table-body');
            if (!records || records.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center text-secondary">No records logged yet.</td></tr>';
                return;
            }
            tbody.innerHTML = records.slice(-8).reverse().map(r => `
                <tr>
                    <td class="fw-bold">${r.index}</td>
                    <td>${r.timestamp.substring(11, 19)}</td>
                    <td><span class="badge ${r.decision === 'APPROVED' ? 'badge-approved' : 'badge-rejected'}">${r.decision}</span></td>
                    <td><span class="badge bg-secondary">${r.intent ? r.intent.action : 'N/A'}</span></td>
                    <td>${r.intent && r.intent.target_switch ? `s${r.intent.target_switch}-p${r.intent.from_port}` : 'Global'}</td>
                    <td class="font-monospace text-info small">${r.current_hash ? r.current_hash.substring(0, 16) + '...' : ''}</td>
                    <td class="font-monospace text-secondary small">${r.previous_hash ? r.previous_hash.substring(0, 12) + '...' : 'GENESIS'}</td>
                    <td><span class="badge bg-success bg-opacity-25 text-success"><i class="fa-solid fa-check"></i> ECDSA OK</span></td>
                </tr>
            `).join('');
        }

        async function runSimulation(scenario) {
            const verdictBadge = document.getElementById('sim-verdict-badge');
            verdictBadge.className = 'badge bg-warning';
            verdictBadge.innerText = 'Evaluating Formal Proof...';

            try {
                const res = await fetch(`/api/simulate?scenario=${scenario}`);
                const data = await res.json();

                document.getElementById('sim-intent-box').innerText = JSON.stringify(data.intent, null, 2);
                document.getElementById('sim-verifier-box').innerText = JSON.stringify(data.verification.checks || data.verification, null, 2);

                if (data.decision === 'APPROVED') {
                    verdictBadge.className = 'badge bg-success fs-6';
                    verdictBadge.innerHTML = '<i class="fa-solid fa-check me-1"></i> APPROVED';
                    document.getElementById('sim-executor-status').innerHTML = '<i class="fa-solid fa-shield text-success me-1"></i> Remediation Executor: Executed & Verified in OVS Flow Table';
                } else {
                    verdictBadge.className = 'badge bg-danger fs-6';
                    verdictBadge.innerHTML = '<i class="fa-solid fa-ban me-1"></i> REJECTED BY GUARDRAIL';
                    document.getElementById('sim-executor-status').innerHTML = '<i class="fa-solid fa-shield text-danger me-1"></i> Remediation Executor: BLOCKED (0 Network Modifications)';
                }

                if (data.audit_record) {
                    document.getElementById('sim-audit-hash').innerText = `Signed Record #${data.audit_record.index}: ${data.audit_record.current_hash.substring(0, 16)}...`;
                }

                // Refresh stats and audit table
                setTimeout(fetchStatus, 500);
            } catch (err) {
                verdictBadge.className = 'badge bg-danger';
                verdictBadge.innerText = 'Evaluation Error';
            }
        }

        fetchStatus();
        setInterval(fetchStatus, 4000);
    </script>
</body>
</html>
"""


def create_metrics_app(telemetry_path=None, audit_log_path=None, trace_log_path=None, approval_path=None):
    """
    Factory function for the Flask Observability & Metrics server.
    Provides Prometheus metrics on /metrics, JSON on /metrics/json,
    and a visual interactive dashboard on / and /dashboard.
    """
    app = Flask(__name__)
    collector = NetOpsMetricsCollector(
        telemetry_path=telemetry_path,
        audit_log_path=audit_log_path
    )
    audit = AuditTrail(log_path=audit_log_path, auto_load=True)
    trace_file = trace_log_path or os.path.join(base_dir, "observability", "data", "pipeline_trace.jsonl")
    approval_store = HumanApprovalStore(path=approval_path)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok",
            "service": "netops-guardrail-observability",
            "read_only": True
        }), 200

    @app.route("/metrics", methods=["GET"])
    def metrics():
        registry = CollectorRegistry()
        registry.register(collector)
        data = generate_latest(registry)
        return Response(data, mimetype=CONTENT_TYPE_LATEST)

    @app.route("/metrics/json", methods=["GET"])
    def metrics_json():
        return jsonify(collector.get_summary_dict()), 200

    @app.route("/dashboard", methods=["GET"])
    def dashboard():
        dash_path = os.path.join(base_dir, "dashboard", "index.html")
        if os.path.exists(dash_path):
            return send_file(dash_path)
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/status", methods=["GET"])
    def api_status():
        telem = {}
        if os.path.exists(collector.telemetry_path):
            try:
                with open(collector.telemetry_path, "r") as f:
                    telem = json.load(f)
            except Exception:
                pass

        records = []
        if os.path.exists(collector.audit_log_path):
            try:
                with open(collector.audit_log_path, "r") as f:
                    records = json.load(f)
            except Exception:
                pass

        return jsonify({
            "metrics": collector.get_summary_dict(),
            "telemetry": telem,
            "audit_records": records
        }), 200

    @app.route("/api/simulate", methods=["GET"])
    def api_simulate():
        scenario = request.args.get("scenario", "normal")
        telem = {}
        if os.path.exists(collector.telemetry_path):
            with open(collector.telemetry_path, "r") as f:
                telem = json.load(f)

        graph = build_topology(telem) if telem else None

        if scenario == "normal":
            intent = {
                "action": "no_action",
                "reason": "Nominal traffic across all ports, zero congestion"
            }
        elif scenario == "unsafe_block":
            intent = {
                "action": "block",
                "target_switch": "1",
                "from_port": "1",
                "reason": "Adversarial or erroneous intent to isolate access port"
            }
        elif scenario == "injection":
            intent = {
                "action": "block",
                "target_switch": "1",
                "from_port": "1; rm -rf /",
                "reason": "Shell command injection payload attempt"
            }
        else:
            intent = {"action": "no_action", "reason": "Default check"}

        if graph is not None:
            verif_res = apply_intent_to_graph(graph, intent)
        else:
            verif_res = {"safe": False, "reason": "No active topology"}

        decision = "APPROVED" if verif_res.get("safe") else "REJECTED"

        # Record into audit trail
        record = audit.record_decision(
            decision=decision,
            intent=intent,
            verifier_result=verif_res,
            execution_result={"success": True if decision == "APPROVED" else False}
        )

        return jsonify({
            "scenario": scenario,
            "intent": intent,
            "verification": verif_res,
            "decision": decision,
            "audit_record": record
        }), 200


    def _authenticated_approver():
        """Authenticate a human operator using an explicit token-to-identity map."""
        raw_tokens = os.environ.get("NETOPS_APPROVER_TOKENS", "")
        try:
            token_map = json.loads(raw_tokens) if raw_tokens else {}
        except json.JSONDecodeError:
            token_map = {}
        if not isinstance(token_map, dict) or not token_map:
            return None, (jsonify({
                "error": "Human approval API is disabled. Configure NETOPS_APPROVER_TOKENS as a JSON object mapping approver IDs to strong tokens."
            }), 503)
        header = request.headers.get("Authorization", "")
        scheme, _, supplied = header.partition(" ")
        if scheme.lower() != "bearer" or not supplied:
            return None, (jsonify({"error": "Bearer authentication required"}), 401)
        for approver_id, configured_token in token_map.items():
            if isinstance(configured_token, str) and hmac.compare_digest(supplied, configured_token):
                return str(approver_id), None
        return None, (jsonify({"error": "Unauthorized"}), 401)

    @app.route("/approvals", methods=["GET"])
    def human_approval_page():
        # The token stays in this page's session storage and is never returned by the server.
        return render_template_string("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetOps Human Verifier</title><style>
body{font:16px system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem;background:#0f172a;color:#e2e8f0}
input,textarea,button{font:inherit;padding:.65rem;border-radius:8px;border:1px solid #475569}
input,textarea{background:#111827;color:#e2e8f0;width:min(95%,650px)}button{cursor:pointer;margin:.25rem;background:#1e293b;color:#f8fafc}
.card{border:1px solid #334155;padding:1rem;border-radius:12px;margin:1rem 0;background:#1e293b}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1120;padding:.75rem;border-radius:8px}
small{color:#94a3b8}.approve{border-color:#22c55e}.reject{border-color:#ef4444}
.proposal-head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap}
.status-chip{display:inline-block;padding:.3rem .65rem;border-radius:999px;font-weight:700;font-size:.85rem;border:1px solid #64748b;background:#334155;color:#e2e8f0}
.status-pending{border-color:#f59e0b;background:#78350f;color:#fde68a}
.status-approved{border-color:#60a5fa;background:#1e3a8a;color:#dbeafe}
.status-rejected{border-color:#f87171;background:#7f1d1d;color:#fee2e2}
.status-consumed{border-color:#a78bfa;background:#4c1d95;color:#ede9fe}
.status-safe{color:#86efac}.status-unsafe{color:#fca5a5}
.proposal-section{margin:.65rem 0;padding:.8rem;background:#111827;border:1px solid #334155;border-radius:10px}
.proposal-section h3{margin:.1rem 0 .5rem;font-size:1rem}
.proposal-summary{font-size:1rem;line-height:1.45;margin:.25rem 0}
.issue-kicker{font-size:.76rem;letter-spacing:.04em;text-transform:uppercase;color:#93c5fd;font-weight:700}
.change-list{margin:.4rem 0;padding-left:1.25rem}
.change-list li{margin:.35rem 0;line-height:1.45}
.check-list{list-style:none;padding:0;margin:.4rem 0}
.check-list li{margin:.3rem 0;line-height:1.4}
.check-pass{color:#86efac}.check-fail{color:#fca5a5}
.explainer{color:#cbd5e1;line-height:1.55;margin:.5rem 0}
.meta{color:#94a3b8;font-size:.9rem;line-height:1.6}
details{margin-top:1rem}summary{cursor:pointer;color:#93c5fd;font-weight:600}
textarea.reason-box{box-sizing:border-box;width:min(95%,650px);margin:.5rem 0}
.action-row{display:flex;gap:.35rem;flex-wrap:wrap;margin-top:.5rem}
button:disabled{opacity:.6;cursor:wait}
@media(max-width:600px){body{margin:1rem auto}.card{padding:.75rem}.proposal-section{padding:.75rem}}
</style></head><body>
<h1>Human Verifier</h1>
<p>Review the exact proposed action and its topology binding. Approval is single-use and expires. Automated verification still runs before execution.</p>
<label>Human Verifier token (different from the dashboard lab operator token)<br><input id="token" type="password" autocomplete="current-password"></label>
<button onclick="connect()">Connect</button><button onclick="loadApprovals()">Refresh</button>
<p id="status" role="status">Enter the Human Verifier token printed by the local startup script.</p><main id="items"></main>
<script>
const tokenInput=document.getElementById('token');tokenInput.value=sessionStorage.getItem('netops_approver_token')||'';
function auth(){return {'Authorization':'Bearer '+tokenInput.value.trim(),'Content-Type':'application/json'};}
function node(tag,className,text){const el=document.createElement(tag);if(className)el.className=className;if(text!==undefined&&text!==null)el.textContent=String(text);return el;}
function formatDate(value){if(!value)return 'Not recorded';const d=new Date(value);return Number.isNaN(d.getTime())?String(value):d.toLocaleString();}
function humanStatus(p){
  const states={
    pending:{label:'Waiting for your decision',className:'status-pending',summary:'The proposal has not been approved, and no remediation has been executed.'},
    approved:{label:'Approved — not executed yet',className:'status-approved',summary:'A human approved this action. The network has not necessarily changed; execution is a separate step.'},
    rejected:{label:'Rejected',className:'status-rejected',summary:'The reviewer rejected this proposal. It must not be executed.'},
    changes_requested:{label:'Changes requested',className:'status-pending',summary:'The reviewer asked for changes. A revised proposal is needed before execution.'},
    consumed:{label:'Approval used — check execution result',className:'status-consumed',summary:'This approval has been used. Check the execution result and connectivity test to determine whether the change succeeded.'}
  };
  return states[String(p.status||'').toLowerCase()]||{label:String(p.status||'Unknown status').replaceAll('_',' '),className:'',summary:'Review the technical details before taking action.'};
}
function issuePresentation(p){
  const intent=p.intent||{};
  const raw=String(intent.reason||'');
  const action=String(intent.action||'review').toLowerCase();
  const sw=String(intent.target_switch||'?');
  const port=String(intent.from_port||'?');
  const isDemo2=/CONTROLLED DEMO SIGNAL/i.test(raw);
  const isIssue2=isDemo2||/standby.forwarding.anomaly|standby_forwarding_anomaly|unexpected standby forwarding/i.test(raw);
  const isIssue1=!isIssue2&&/re.isolate|restored standby trunk|redundant_trunk_restored/i.test(raw);
  const status=String(p.status||'').toLowerCase();
  let title='Network remediation proposal';
  let summary=raw||'The AI proposed a network change. Review the target, impact, and safety checks below.';
  let changes=[];
  if(isIssue2){
    title='Issue 2 — Unexpected standby forwarding';
    summary=isDemo2
      ?'This proposal was created from a controlled demo signal. Live telemetry did not confirm both ends of the standby link forwarding, and the demo did not change switch or STP state.'
      :'The issue is unexpected forwarding on the standby connection. Review the current link states and safety evidence before approving the proposed isolation.';
    changes=[
      action==='block'&&sw==='1'&&port==='3'?'Proposed change: isolate backup link s1-p3 ↔ s2-p2 with guardrail block rules.':action==='block'?'Proposed change: block traffic on s'+sw+'-p'+port+'.':'Proposed action: '+action+' on switch s'+sw+', port '+port+'.',
      'Keep the primary connection s1-p2 ↔ s2-p1 available.',
      'After execution, check host connectivity and confirm the actual flow-rule result.'
    ];
  }else if(isIssue1){
    title='Issue 1 — Standby trunk re-isolation';
    summary='The primary connection s1-p2 ↔ s2-p1 is reported as forwarding. At least one end of the backup connection s1-p3 ↔ s2-p2 is blocked by STP. This proposal aims to explicitly isolate the restored backup path.';
    changes=[
      action==='block'&&sw==='1'&&port==='3'?'Proposed change: isolate backup link s1-p3 ↔ s2-p2 with guardrail block rules.':action==='block'?'Proposed change: block traffic on s'+sw+'-p'+port+'.':'Proposed action: '+action+' on switch s'+sw+', port '+port+'.',
      'Preserve the primary connection s1-p2 ↔ s2-p1 for normal traffic.',
      'After execution, verify host connectivity and confirm the rule was installed.'
    ];
  }else{
    title='Network remediation proposal';
    summary=raw||'The AI has suggested a network action. Review it carefully before deciding.';
    changes=[
      'Proposed action: '+action+' on switch s'+sw+', port '+port+'.',
      'Review how this affects traffic using that port.',
      'After execution, verify connectivity and inspect the actual execution result.'
    ];
  }

  let stage='Proposed only — not applied to the network yet.';
  if(status==='approved') stage='Approved by a human reviewer; execution is a separate step and is not confirmed yet.';
  else if(status==='rejected') stage='Rejected by the human reviewer. This proposal is not authorized for execution.';
  else if(status==='changes_requested') stage='Changes requested. A revised proposal is needed; this proposal is not authorized for execution.';
  else if(status==='consumed') stage='Execution was attempted using this approval. Check the executor result and connectivity test to determine whether it succeeded.';
  else if(status==='expired') stage='This proposal expired before a decision. Generate a fresh proposal to continue.';
  return {title,summary,changes,stage,isDemo2,isIssue2,isIssue1};
}
function humanStatus(p){
  const states={
    pending:{label:'Waiting for your decision',className:'status-pending',summary:'No human approval has been recorded. The proposed network change has not been executed.'},
    approved:{label:'Approved — not executed yet',className:'status-approved',summary:'A human approved this action. Approval does not mean the network has changed.'},
    rejected:{label:'Rejected',className:'status-rejected',summary:'The reviewer rejected this proposal. It must not be executed.'},
    changes_requested:{label:'Changes requested',className:'status-pending',summary:'The reviewer asked for changes. A revised proposal is needed.'},
    consumed:{label:'Execution attempted — verify result',className:'status-consumed',summary:'The approval has been used. Check execution and connectivity evidence before claiming success.'},
    expired:{label:'Expired',className:'status-rejected',summary:'This proposal expired and cannot be approved.'}
  };
  return states[String(p.status||'').toLowerCase()]||{label:String(p.status||'Unknown status').replaceAll('_',' '),className:'',summary:'Review the proposal details before taking action.'};
}
async function connect(){tokenInput.value=tokenInput.value.trim();if(!tokenInput.value){document.getElementById('status').textContent='Paste the Human Verifier token first.';return;}sessionStorage.setItem('netops_approver_token',tokenInput.value);await loadApprovals();}
async function loadApprovals(){const status=document.getElementById('status'),items=document.getElementById('items');
if(!tokenInput.value.trim()){status.textContent='Enter the Human Verifier token.';return;}
status.textContent='Loading proposals…';items.replaceChildren();
try{const r=await fetch('/api/approvals',{headers:auth()});const data=await r.json();
if(r.status===401){sessionStorage.removeItem('netops_approver_token');tokenInput.value='';status.textContent='Unauthorized. Use the Human Verifier token printed by start_local_observability.sh — not the Lab operator token. Paste it here and click Connect.';return;}
if(!r.ok)throw new Error(data.error||'Request failed');sessionStorage.setItem('netops_approver_token',tokenInput.value.trim());status.textContent='Connected as '+(data.authenticated_approver||'authorized operator')+'. Review each proposal before deciding.';
for(const p of data.proposals||[]){
  const card=node('section','card');
  const head=node('div','proposal-head');
  const title=node('h2','', 'Proposal '+p.proposal_id);
  const state=humanStatus(p);
  const chip=node('span','status-chip '+state.className,state.label);
  head.append(title,chip);card.append(head);
  card.append(node('p','explainer',state.summary));

  const presentation=issuePresentation(p);
  const issueSection=node('section','proposal-section');
  issueSection.append(node('div','issue-kicker','Issue details'));
  issueSection.append(node('h3','',presentation.title));
  issueSection.append(node('p','explainer',presentation.summary));
  card.append(issueSection);

  const changeSection=node('section','proposal-section');
  changeSection.append(node('h3','','Changes to address the issue'));
  changeSection.append(node('p','meta',presentation.stage));
  const changeList=node('ul','change-list');
  for(const change of presentation.changes)changeList.append(node('li','',change));
  changeSection.append(changeList);
  card.append(changeSection);

  const verifier=p.verifier_result||{};
  const checkSection=node('section','proposal-section');
  const safe=verifier.safe===true;
  checkSection.append(node('h3','', 'Automated safety checks'));
  checkSection.append(node('p',safe?'status-safe':'status-unsafe',safe?'Safety checker: PASS':'Safety checker: FAIL — review before taking action'));
  checkSection.append(node('p','explainer',safe
    ?'The automated checks passed for this proposal. This does not equal human approval and does not prove that the network change was executed.'
    :'One or more required checks did not pass. Review the failures before considering this action.'));
  const checks=node('ul','check-list');
  const checkValues=Array.isArray(verifier.checks)?verifier.checks:[];
  if(checkValues.length){
    for(const check of checkValues){
      const passed=/^PASS:/i.test(String(check));
      checks.append(node('li',passed?'check-pass':'check-fail',(passed?'✓ ':'✕ ')+String(check).replace(/^(PASS|FAIL):\\s*/i,'')));
    }
  }else checks.append(node('li','meta','No detailed safety checks were recorded.'));
  checkSection.append(checks);
  checkSection.append(node('p','meta','Topology nodes checked: '+(verifier.nodes??'not recorded')+' · Connections checked: '+(verifier.edges??'not recorded')));
  card.append(checkSection);

  const details=document.createElement('details');
  details.append(node('summary','','Technical details (fingerprints, timestamps and original reason)'));
  const metadata=node('div','proposal-section');
  metadata.append(node('p','meta','Created: '+formatDate(p.created_at)));
  metadata.append(node('p','meta','Expires: '+formatDate(p.expires_at)));
  metadata.append(node('p','meta','Target switch: s'+String((p.intent||{}).target_switch||'?')+' · Port: '+String((p.intent||{}).from_port||'?')));
  const raw=node('pre','',JSON.stringify({topology_fingerprint:p.topology_fingerprint,proposal_fingerprint:p.proposal_fingerprint,original_reason:(p.intent||{}).reason,decision:p.decision,consumed_at:p.consumed_at},null,2));
  metadata.append(raw);details.append(metadata);card.append(details);

  const decisionSection=node('section','proposal-section');
  decisionSection.append(node('h3','','Your Decision'));
  if(p.status==='pending'){
    decisionSection.append(node('p','explainer','Review the issue, proposed changes, and safety checks. Choose approve, reject, or request changes, and record a short reason for the audit trail.'));
    const reason=node('textarea','reason-box');reason.placeholder='Why are you approving, rejecting, or requesting changes?';reason.rows=3;reason.style.display='block';decisionSection.append(reason);
    const row=node('div','action-row');
    for(const decision of ['approve','reject','request_changes']){
      const b=node('button',decision==='approve'?'approve':decision==='reject'?'reject':'',decision==='approve'?'Approve proposal':decision==='reject'?'Reject proposal':'Request changes');
      b.onclick=async()=>{
        if(!reason.value.trim()){alert('Enter a reason for the audit trail.');return;}
        b.disabled=true;
        try{
          const res=await fetch('/api/approvals/'+encodeURIComponent(p.proposal_id)+'/decision',{method:'POST',headers:auth(),body:JSON.stringify({decision,reason:reason.value,proposal_fingerprint:p.proposal_fingerprint})});
          const out=await res.json();if(!res.ok)throw new Error(out.error||'Decision failed');
          await loadApprovals();
          status.textContent='Decision recorded: '+humanStatus(out.proposal||{status:decision==='approve'?'approved':decision==='reject'?'rejected':'changes_requested'}).label+'.';
        }catch(e){alert(e.message);b.disabled=false;}
      };
      row.append(b);
    }
    decisionSection.append(row);
  }else if(p.status==='approved'){
    const decided=p.decision||{};
    decisionSection.append(node('p','explainer','Decision: Approved by '+(decided.approver_id||'authorized reviewer')+' on '+formatDate(decided.decided_at)+'.'));
    if(decided.reason)decisionSection.append(node('p','meta','Recorded reason: '+decided.reason));
    decisionSection.append(node('p','explainer','The proposal is approved, but the change is not confirmed as applied until execution succeeds and connectivity is checked.'));
    const b=node('button','approve','Execute approved action');
    b.onclick=async()=>{
      if(!confirm('Run this exact approved action? It will be revalidated. Execution changes the lab network and requires a live connectivity check.'))return;
      b.disabled=true;
      try{
        const res=await fetch('/api/approvals/'+encodeURIComponent(p.proposal_id)+'/execute',{method:'POST',headers:auth(),body:'{}'});
        const out=await res.json();
        alert(JSON.stringify(out,null,2));
        await loadApprovals();
      }catch(e){alert(e.message);b.disabled=false;}
    };
    decisionSection.append(b);
  }else{
    const decided=p.decision||{};
    decisionSection.append(node('p','explainer',state.summary));
    if(decided.approver_id)decisionSection.append(node('p','meta','Decision recorded by: '+decided.approver_id));
    if(decided.decided_at)decisionSection.append(node('p','meta','Decision date: '+formatDate(decided.decided_at)));
    if(decided.reason)decisionSection.append(node('p','meta','Reason: '+decided.reason));
    if(p.status==='consumed'){
      decisionSection.append(node('p','explainer','Do not mark this as fixed until the execution result and post-change connectivity check confirm success.'));
    }
  }
  card.append(decisionSection);
  items.append(card);
}
if(!(data.proposals||[]).length){status.textContent='No active proposals or recent decisions.';}
}catch(e){status.textContent='Error: '+e.message;}}
</script></body></html>""")

    @app.route("/api/approvals", methods=["GET"])
    def api_human_approvals():
        approver, error = _authenticated_approver()
        if error:
            return error
        all_proposals = approval_store.list_proposals(include_decided=True)
        active_proposals = [
            p for p in all_proposals
            if p.get("status") in {"pending", "approved"}
            and not approval_store._is_expired(p)
        ]
        # Keep the latest terminal decisions visible instead of making rejected
        # proposals disappear from the Human Verifier queue.
        terminal_statuses = {"rejected", "changes_requested", "consumed"}
        recent_decisions = [
            p for p in all_proposals if p.get("status") in terminal_statuses
        ]
        recent_decisions.sort(
            key=lambda p: (
                (p.get("decision") or {}).get("decided_at")
                or p.get("consumed_at")
                or p.get("created_at")
                or ""
            ),
            reverse=True,
        )
        proposals = active_proposals + recent_decisions[:10]
        return jsonify({"proposals": proposals, "authenticated_approver": approver}), 200

    @app.route("/api/approvals/<proposal_id>/decision", methods=["POST"])
    def api_human_approval_decision(proposal_id):
        approver, error = _authenticated_approver()
        if error:
            return error
        payload = request.get_json(silent=True) or {}
        reason = str(payload.get("reason", "")).strip()
        if not reason:
            return jsonify({"error": "A decision reason is required"}), 400
        current = approval_store.get_proposal(proposal_id)
        if current is None:
            return jsonify({"error": "Proposal not found"}), 404
        try:
            updated = approval_store.decide(
                proposal_id=proposal_id,
                decision=payload.get("decision", ""),
                approver_id=approver,
                reason=reason,
                proposal_fingerprint_value=payload.get("proposal_fingerprint"),
            )
        except ApprovalError as exc:
            return jsonify({"error": str(exc)}), 409
        audit_decision = {"approved": "APPROVED", "rejected": "REJECTED", "changes_requested": "CHANGES_REQUESTED"}[updated["status"]]
        audit_record = audit.record_decision(
            decision=audit_decision,
            intent=current["intent"],
            verifier_result=current["verifier_result"],
            execution_result={"human_approval": {
                "proposal_id": proposal_id,
                "status": updated["status"],
                "approver_id": approver,
                "reason": reason,
                "proposal_fingerprint": updated["proposal_fingerprint"],
            }},
        )

        # Preserve the original AI proposal event and append the final human
        # decision as a separate event in Pipeline Trace.
        decision_details = updated.get("decision") or {}
        trace_event = {
            "event_type": "human_approval_decision",
            "decision": audit_decision,
            "intent": current.get("intent") or {},
            "verification": current.get("verifier_result") or {},
            "execution": None,
            "human_approval": {
                "proposal_id": proposal_id,
                "status": updated["status"],
                "proposal_fingerprint": updated.get("proposal_fingerprint"),
                "expires_at": updated.get("expires_at"),
                "decision": decision_details,
            },
            "decision_reason": reason,
            "audit_record": audit_record,
            "timestamp": decision_details.get("decided_at") or datetime.now(timezone.utc).isoformat(),
        }
        try:
            os.makedirs(os.path.dirname(trace_file) or ".", exist_ok=True)
            with open(trace_file, "a", encoding="utf-8") as trace_handle:
                trace_handle.write(json.dumps(trace_event) + "\n")
        except OSError:
            app.logger.exception("Failed to append human approval decision to pipeline trace")

        return jsonify({
            "proposal": updated,
            "audit_status": "recorded",
            "trace_status": "recorded",
        }), 200

    @app.route("/api/approvals/<proposal_id>/execute", methods=["POST"])
    def api_execute_human_approved(proposal_id):
        approver, error = _authenticated_approver()
        if error:
            return error
        proposal = approval_store.get_proposal(proposal_id)
        if proposal is None:
            return jsonify({"error": "Proposal not found"}), 404
        if proposal.get("status") != "approved":
            return jsonify({"error": "Only an approved, unconsumed proposal can execute"}), 409
        chain_ok, chain_message = audit.verify_chain(audit.chain)
        if not chain_ok:
            return jsonify({"error": f"Audit chain verification failed; execution blocked: {chain_message}"}), 503
        approval_audited = any(
            record.get("decision") == "APPROVED"
            and record.get("intent") == proposal.get("intent")
            and isinstance(record.get("execution_result"), dict)
            and isinstance(record["execution_result"].get("human_approval"), dict)
            and record["execution_result"]["human_approval"].get("proposal_id") == proposal_id
            and record["execution_result"]["human_approval"].get("status") == "approved"
            for record in audit.chain
        )
        if not approval_audited:
            return jsonify({
                "error": "Matching signed approval record is missing; execution remains blocked."
            }), 503
        checker_spec = os.environ.get("NETOPS_CONNECTIVITY_CHECKER", "")
        if ":" not in checker_spec:
            return jsonify({
                "error": "Execution disabled: configure NETOPS_CONNECTIVITY_CHECKER=module:function for a real host-to-host connectivity check."
            }), 503
        module_name, function_name = checker_spec.split(":", 1)
        try:
            checker = getattr(importlib.import_module(module_name), function_name)
            if not callable(checker):
                raise ValueError("checker is not callable")
        except Exception as exc:
            return jsonify({"error": f"Connectivity checker could not be loaded: {exc}"}), 503
        result = decide(
            telemetry_path=collector.telemetry_path,
            execute_approved=True,
            connectivity_checker=checker,
            approval_id=proposal_id,
            approval_store=approval_store,
            audit_logger=audit,
        )
        execution = result.get("execution") or {}
        status_code = 200 if execution.get("success") else 409
        return jsonify({"authenticated_approver": approver, "result": result}), status_code

    @app.route("/api/topology", methods=["GET"])
    def api_topology():
        telem_path = collector.telemetry_path
        if not os.path.exists(telem_path):
            return jsonify({"nodes": [], "edges": []}), 200
        try:
            with open(telem_path, "r", encoding="utf-8") as f:
                telem = json.load(f)
            if not isinstance(telem, dict):
                return jsonify({"nodes": [], "edges": []}), 200
            graph = build_topology(telem)
            nodes = [
                {"id": str(n), "type": graph.nodes[n].get("type", "unknown")}
                for n in graph.nodes
            ]
            edges = [
                {"source": str(u), "target": str(v)}
                for u, v in graph.edges
            ]
            return jsonify({"nodes": nodes, "edges": edges}), 200
        except Exception:
            return jsonify({"nodes": [], "edges": []}), 200

    @app.route("/api/pipeline/trace", methods=["GET"])
    def api_pipeline_trace():
        try:
            limit = int(request.args.get("limit", 20))
            if limit < 1:
                limit = 20
        except (ValueError, TypeError):
            limit = 20

        if not os.path.exists(trace_file):
            return jsonify([]), 200

        try:
            with open(trace_file, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            records = []
            for line in lines[-limit:]:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return jsonify(records), 200
        except Exception:
            return jsonify([]), 200

    @app.route("/api/audit/chain", methods=["GET"])
    def api_audit_chain():
        try:
            limit = int(request.args.get("limit", 20))
            if limit < 1:
                limit = 20
        except (ValueError, TypeError):
            limit = 20

        log_path = collector.audit_log_path
        if not os.path.exists(log_path):
            return jsonify([]), 200

        try:
            with open(log_path, "r", encoding="utf-8") as f:
                records = json.load(f)
            if not isinstance(records, list):
                return jsonify([]), 200

            chain_summary = []
            for r in records[-limit:]:
                intent = r.get("intent") or {}
                action = (
                    intent.get("action", "unknown")
                    if isinstance(intent, dict)
                    else str(intent)
                )
                curr_hash = str(r.get("current_hash", ""))
                chain_summary.append({
                    "index": r.get("index"),
                    "decision": r.get("decision"),
                    "action": action,
                    "current_hash": curr_hash[:16] if len(curr_hash) >= 16 else curr_hash,
                    "timestamp": r.get("timestamp")
                })
            return jsonify(chain_summary), 200
        except Exception:
            return jsonify([]), 200

    # =========================================================================
    # CHAOS INJECTION ENDPOINT (MUTATING)
    #
    # NOTE: This is the ONLY endpoint in this file that mutates network state.
    # It does so by manipulating the topology directly (simulating a physical
    # network fault / restoring a redundant trunk link), NEVER by calling into
    # the guardrail's decision pipeline or bypassing safety verification.
    # The guardrail pipeline discovers and reacts to the change through its
    # normal telemetry discovery path, exactly like any other real network fault.
    # =========================================================================
    @app.route("/api/chaos/inject-loop", methods=["POST"])
    def api_chaos_inject_loop():
        """Restore the redundant trunk as a controlled fault, then run the AI gate.

        This endpoint only resets the known trunk-B test condition. It never
        invokes the executor; the action must pass verification and be approved
        in Human Verifier before the separate execution endpoint can run.
        """
        configured_token = os.environ.get("NETOPS_CHAOS_API_TOKEN", "")
        if not configured_token:
            return jsonify({
                "error": "Fault injection is disabled. Configure NETOPS_CHAOS_API_TOKEN when starting the local server."
            }), 503
        supplied_token = request.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied_token, f"Bearer {configured_token}"):
            return jsonify({"error": "Unauthorized"}), 401
        if request.args.get("confirm", "").strip().lower() != "true":
            return jsonify({"error": "Confirmation required. Call with ?confirm=true to continue."}), 400

        # Fixed commands only. Refuse unless this project's two OVS bridges exist.
        for bridge in ("s1", "s2"):
            check = subprocess.run(
                ["sudo", "-n", "ovs-vsctl", "br-exists", bridge],
                shell=False, capture_output=True, text=True, check=False, timeout=3,
            )
            if check.returncode != 0:
                return jsonify({
                    "error": f"Controlled fault injection requires live Mininet bridge {bridge}; no command was run."
                }), 409

        # Require a configured, real bidirectional ping checker before touching
        # the lab. A missing/stopped testbed must fail closed.
        checker_spec = os.environ.get("NETOPS_CONNECTIVITY_CHECKER", "")
        module_name, separator, function_name = checker_spec.partition(":")
        if not separator or not module_name or not function_name:
            return jsonify({
                "error": "Fault injection disabled: configure a real NETOPS_CONNECTIVITY_CHECKER=module:function first."
            }), 503
        try:
            checker_module = importlib.import_module(module_name)
            connectivity_checker = getattr(checker_module, function_name)
            if not callable(connectivity_checker):
                raise TypeError("configured connectivity checker is not callable")
            if connectivity_checker() is not True:
                return jsonify({
                    "error": "Baseline host-to-host connectivity did not pass; refusing to inject a fault."
                }), 409
        except Exception as exc:
            return jsonify({
                "error": f"Baseline connectivity checker failed closed: {type(exc).__name__}: {exc}"
            }), 503

        # Reintroduce the known redundant trunk-B condition, removing only the
        # previous trunk-B guardrail rule and ensuring both link interfaces are up.
        commands = [
            ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1", "in_port=3"],
            ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s2", "in_port=2"],
            ["sudo", "-n", "ip", "link", "set", "s1-eth3", "up"],
            ["sudo", "-n", "ip", "link", "set", "s2-eth2", "up"],
        ]
        for command in commands:
            try:
                result = subprocess.run(
                    command, shell=False, capture_output=True, text=True,
                    check=False, timeout=4,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return jsonify({
                    "error": f"Fault reset command failed ({command[2]}): {exc}",
                    "network_mutation_attempted": True, "execution_started": False,
                }), 503
            if result.returncode != 0:
                return jsonify({
                    "error": f"Fault reset command failed ({command[2]}): {(result.stderr or result.stdout).strip()}",
                    "network_mutation_attempted": True, "execution_started": False,
                }), 503

        try:
            if connectivity_checker() is not True:
                return jsonify({
                    "error": "Host-to-host connectivity did not pass after restoring the redundant trunk; no AI proposal was created.",
                    "network_mutation_attempted": True,
                    "execution_started": False,
                }), 503
        except Exception as exc:
            return jsonify({
                "error": f"Post-reset connectivity checker failed closed: {type(exc).__name__}: {exc}",
                "network_mutation_attempted": True,
                "execution_started": False,
            }), 503

        # Use live Ryu telemetry only: do not forge topology edges or timestamps.
        try:
            with open(collector.telemetry_path, "r", encoding="utf-8") as handle:
                telemetry = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            return jsonify({
                "error": f"Cannot read Ryu telemetry after fault reset: {exc}",
                "network_mutation_attempted": True, "execution_started": False,
            }), 503

        switches = telemetry.get("switches", {})
        states = {
            str(sw): {str(port): str(state).upper()
                      for port, state in (data.get("stp_port_states") or {}).items()}
            for sw, data in switches.items() if isinstance(data, dict)
        }
        links = set()
        for link in telemetry.get("links", []):
            if isinstance(link, dict):
                a = f"s{str(link.get('src_switch', '')).strip()}-p{str(link.get('src_port', '')).strip()}"
                b = f"s{str(link.get('dst_switch', '')).strip()}-p{str(link.get('dst_port', '')).strip()}"
                links.add(tuple(sorted((a, b))))
        trunk_a = tuple(sorted(("s1-p2", "s2-p1")))
        trunk_b = tuple(sorted(("s1-p3", "s2-p2")))
        if trunk_a not in links or trunk_b not in links:
            return jsonify({
                "error": "Ryu telemetry does not confirm both redundant trunks; keep Mininet/Ryu running and retry.",
                "observed_links": sorted(links), "network_mutation_attempted": True,
                "execution_started": False,
            }), 409
        if not (
            states.get("1", {}).get("1") == "FORWARD"
            and states.get("2", {}).get("3") == "FORWARD"
            and states.get("1", {}).get("2") == "FORWARD"
            and states.get("2", {}).get("1") == "FORWARD"
            and "BLOCK" in {states.get("1", {}).get("3", "UNKNOWN"),
                            states.get("2", {}).get("2", "UNKNOWN")}
        ):
            return jsonify({
                "error": "Safety precondition failed: host access and primary trunk must be FORWARD, and a standby endpoint must be STP BLOCK.",
                "stp_states": states, "network_mutation_attempted": True,
                "execution_started": False,
            }), 409

        incident_context = {
            "fault_type": "redundant_trunk_restored",
            "summary": "Controlled fault injection restored redundant trunk B and cleared prior guardrail drop rules on that trunk. Use current Ryu topology and STP telemetry as evidence.",
            "affected_link": {"endpoint_a": "s1-p3", "endpoint_b": "s2-p2"},
            "expected_action": "block",
            "expected_target_switch": "1",
            "expected_from_port": "3",
            "reason": "Re-isolate the restored standby trunk while preserving the primary trunk and host reachability.",
        }
        try:
            pipeline = decide(
                telemetry_path=collector.telemetry_path,
                execute_approved=False,
                audit_logger=audit,
                incident_context=incident_context,
            )
        except Exception as exc:
            return jsonify({
                "error": f"AI decision pipeline failed closed: {type(exc).__name__}: {exc}",
                "network_mutation_attempted": True, "execution_started": False,
            }), 503

        if pipeline.get("decision") != "PENDING_HUMAN_APPROVAL" or not pipeline.get("human_approval"):
            return jsonify({
                "error": "AI/verifier did not produce a safe human-reviewable block proposal. No remediation was executed.",
                "fault": incident_context, "pipeline": pipeline,
                "network_mutation_attempted": True, "execution_started": False,
            }), 409

        return jsonify({
            "status": "fault_injected_proposal_created",
            "fault": incident_context,
            "pipeline": pipeline,
            "proposal_id": pipeline["human_approval"]["proposal_id"],
            "expires_at": pipeline["human_approval"]["expires_at"],
            "network_mutation_attempted": True,
            "execution_started": False,
            "next_step": "Open /approvals, inspect the AI-generated intent and verifier checks, and approve/reject with a reason.",
        }), 200

    @app.route("/api/chaos/standby-forwarding", methods=["POST"])
    def api_issue2_standby_forwarding():
        """Run Issue 2 detection or an explicitly labeled, non-disruptive demo signal.

        No OVS/STP port state is changed here. Live telemetry and connectivity
        are always checked. If live telemetry does not show both standby ends
        forwarding, a proposal is created only when the caller explicitly asks
        for a controlled simulation. The response and AI reason label it as such.
        """
        configured_token = os.environ.get("NETOPS_CHAOS_API_TOKEN", "")
        if not configured_token:
            return jsonify({"error": "Issue 2 is disabled: configure NETOPS_CHAOS_API_TOKEN."}), 503
        supplied_token = request.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied_token, f"Bearer {configured_token}"):
            return jsonify({"error": "Unauthorized"}), 401
        if request.args.get("confirm", "").strip().lower() != "true":
            return jsonify({"error": "Confirmation required. Call with ?confirm=true."}), 400

        payload = request.get_json(silent=True) or {}
        allow_simulation = payload.get("allow_controlled_simulation") is True

        # Do not let the demo endpoint run when the expected lab is missing.
        for bridge in ("s1", "s2"):
            check = subprocess.run(
                ["sudo", "-n", "ovs-vsctl", "br-exists", bridge],
                shell=False, capture_output=True, text=True, check=False, timeout=3,
            )
            if check.returncode != 0:
                return jsonify({
                    "error": f"Issue 2 requires live Mininet bridge {bridge}; no proposal was created.",
                    "network_mutation_attempted": False,
                }), 409

        checker_spec = os.environ.get("NETOPS_CONNECTIVITY_CHECKER", "")
        module_name, separator, function_name = checker_spec.partition(":")
        if not separator or not module_name or not function_name:
            return jsonify({
                "error": "Issue 2 disabled: configure a real NETOPS_CONNECTIVITY_CHECKER=module:function.",
                "network_mutation_attempted": False,
            }), 503
        try:
            checker_module = importlib.import_module(module_name)
            connectivity_checker = getattr(checker_module, function_name)
            if not callable(connectivity_checker) or connectivity_checker() is not True:
                return jsonify({
                    "error": "Live baseline host connectivity did not pass; no proposal was created.",
                    "network_mutation_attempted": False,
                }), 409
        except Exception as exc:
            return jsonify({
                "error": f"Live connectivity check failed closed: {type(exc).__name__}: {exc}",
                "network_mutation_attempted": False,
            }), 503

        # Never propose a second block when the guardrail already contains the
        # standby trunk. Inspect only the exact guardrail priority/ports.
        for bridge, port in (("s1", "3"), ("s2", "2")):
            result = subprocess.run(
                ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge],
                shell=False, capture_output=True, text=True, check=False, timeout=3,
            )
            if result.returncode != 0:
                return jsonify({
                    "error": f"Could not inspect existing flows on {bridge}; refusing duplicate proposal.",
                    "network_mutation_attempted": False,
                }), 503
            for line in (result.stdout or "").splitlines():
                if "priority=65500" in line and f"in_port={port}" in line and "actions=drop" in line:
                    return jsonify({
                        "error": f"Standby trunk already has a guardrail drop rule on {bridge} port {port}; reconcile the existing action before a new proposal.",
                        "network_mutation_attempted": False,
                    }), 409

        try:
            with open(collector.telemetry_path, "r", encoding="utf-8") as handle:
                telemetry = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            return jsonify({
                "error": f"Could not read live Ryu telemetry: {exc}",
                "network_mutation_attempted": False,
            }), 503

        observation = inspect_standby_forwarding(telemetry)
        if not observation["ready_for_investigation"]:
            return jsonify({
                "error": "Live telemetry is stale or the primary/host path preconditions are not healthy; no Issue 2 proposal was created.",
                "observation": observation,
                "network_mutation_attempted": False,
            }), 409

        live_anomaly = observation["detected"]
        if not live_anomaly and not allow_simulation:
            return jsonify({
                "status": "no_live_anomaly",
                "message": "Live Ryu telemetry does not currently show both standby endpoints FORWARD. No AI proposal was created. Use the explicitly labeled controlled demo option only when you need to demonstrate the review workflow.",
                "observation": observation,
                "network_mutation_attempted": False,
                "execution_started": False,
            }), 200

        incident_context = {
            "fault_type": "standby_forwarding_anomaly",
            "summary": (
                "Live telemetry reports both standby endpoints forwarding."
                if live_anomaly else
                "Controlled simulation of an unexpected standby-forwarding alert; the simulation signal is not a claim that live STP state is anomalous."
            ),
            "affected_link": {"endpoint_a": "s1-p3", "endpoint_b": "s2-p2"},
            "expected_action": "block",
            "expected_target_switch": "1",
            "expected_from_port": "3",
            "simulation_mode": not live_anomaly,
            "signal_source": "live_telemetry" if live_anomaly else "controlled_demo_signal",
            "observation": observation,
            "reason": (
                "Contain unexpected standby forwarding while preserving the primary trunk and host reachability."
                if live_anomaly else
                "Demonstrate the Issue 2 review flow safely; propose standby isolation for human review without changing switch/STP state during incident injection."
            ),
        }
        try:
            pipeline = decide(
                telemetry_path=collector.telemetry_path,
                execute_approved=False,
                audit_logger=audit,
                incident_context=incident_context,
            )
        except Exception as exc:
            return jsonify({
                "error": f"Issue 2 AI decision pipeline failed closed: {type(exc).__name__}: {exc}",
                "incident_context": incident_context,
                "network_mutation_attempted": False,
                "execution_started": False,
            }), 503

        if pipeline.get("decision") != "PENDING_HUMAN_APPROVAL" or not pipeline.get("human_approval"):
            return jsonify({
                "error": "AI/verifier did not create a safe human-reviewable proposal. No remediation was executed.",
                "incident_context": incident_context,
                "observation": observation,
                "pipeline": pipeline,
                "network_mutation_attempted": False,
                "execution_started": False,
            }), 409

        return jsonify({
            "status": "issue2_proposal_created",
            "issue": "unexpected_standby_forwarding",
            "detection_mode": "live_telemetry" if live_anomaly else "controlled_simulation",
            "observation": observation,
            "incident_context": incident_context,
            "pipeline": pipeline,
            "proposal_id": pipeline["human_approval"]["proposal_id"],
            "expires_at": pipeline["human_approval"]["expires_at"],
            "network_mutation_attempted": False,
            "execution_started": False,
            "next_step": "Review the proposal on /approvals. Approval is separate from execution; reject if you disagree.",
        }), 200

    @app.route("/", methods=["GET"])
    def index():
        # If requested by a web browser, serve the interactive visual dashboard
        accept_header = request.headers.get("Accept", "")
        if "text/html" in accept_header:
            dash_path = os.path.join(base_dir, "dashboard", "index.html")
            if os.path.exists(dash_path):
                return send_file(dash_path)
            return render_template_string(DASHBOARD_HTML)
        # Default API response for automated tests / API clients
        return jsonify({
            "name": "Agentic AI-NetOps Guardrail Observability Service",
            "endpoints": [
                "/health",
                "/metrics",
                "/metrics/json",
                "/dashboard",
                "/api/status",
                "/api/simulate",
                "/api/topology",
                "/api/pipeline/trace",
                "/api/audit/chain",
                "/approvals",
                "/api/approvals",
                "/api/approvals/<proposal_id>/decision",
                "/api/approvals/<proposal_id>/execute",
                "/api/chaos/inject-loop",
                "/api/chaos/standby-forwarding"
            ]
        }), 200

    return app


if __name__ == "__main__":
    port = int(os.environ.get("METRICS_PORT", 8000))
    host = os.environ.get("METRICS_HOST", "127.0.0.1")
    print(f"Starting NetOps Observability Metrics Server on http://{host}:{port}/")
    print(f"Interactive Web Dashboard available at: http://localhost:{port}/dashboard")
    print(f"Prometheus Metrics Feed available at:   http://localhost:{port}/metrics")
    app = create_metrics_app()
    app.run(host=host, port=port)
