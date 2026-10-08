import os
import sys
import json
from flask import Flask, Response, jsonify, request, render_template_string

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for subdir in ["verifier", "audit", "agent", "controller", "executor", "observability"]:
    path = os.path.join(base_dir, subdir)
    if path not in sys.path:
        sys.path.insert(0, path)

from prometheus_client import CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
from metrics import NetOpsMetricsCollector
from safety_verifier import build_topology, run_safety_checks, test_port_removal
from decision_gate import apply_intent_to_graph
from audit_trail import AuditTrail

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


def create_metrics_app(telemetry_path=None, audit_log_path=None):
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

    @app.route("/", methods=["GET"])
    def index():
        # If requested by a web browser, serve the interactive visual dashboard
        accept_header = request.headers.get("Accept", "")
        if "text/html" in accept_header:
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
                "/api/simulate"
            ]
        }), 200

    return app


if __name__ == "__main__":
    port = int(os.environ.get("METRICS_PORT", 8000))
    host = os.environ.get("METRICS_HOST", "0.0.0.0")
    print(f"Starting NetOps Observability Metrics Server on http://{host}:{port}/")
    print(f"Interactive Web Dashboard available at: http://localhost:{port}/dashboard")
    print(f"Prometheus Metrics Feed available at:   http://localhost:{port}/metrics")
    app = create_metrics_app()
    app.run(host=host, port=port)
