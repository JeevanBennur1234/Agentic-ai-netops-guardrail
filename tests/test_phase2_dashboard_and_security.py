"""Phase 2 verification tests for dashboard template integrity, security, and endpoints."""

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops_guardrail.netops_paths import NETOPS_HOME
from netops_guardrail.observability.server import create_metrics_app

DASHBOARD_PATHS = [
    NETOPS_HOME / "dashboard" / "index.html",
    NETOPS_HOME / "src" / "netops_guardrail" / "observability" / "templates" / "dashboard.html",
]

BANNED_STRINGS = [
    "simulatedPacketCount",
    "drawSimulatedPackets",
    "packet-overlay",
    "/api/simulate",
    "31.9 ms",
    "Simulated packets",
    "Audit Chain",
]

REQUIRED_ELEMENT_IDS = [
    "preflight-card",
    "pipeline-timeline-container",
    "operator-token",
    "audit-record-id",
    "audit-current-hash",
    "stale-telemetry-banner",
    "fault-select",
    "btn-inject-fault",
    "btn-restore-lab",
    "btn-approve-proposal",
    "btn-reject-proposal",
    "btn-execute-remediation",
    "btn-acknowledge-recommendation",
    "recommendation-ack-reason",
]


@pytest.mark.parametrize("dash_path", DASHBOARD_PATHS)
def test_banned_strings_completely_absent(dash_path: Path):
    """Ensure no simulated packet, mock latency, or simulation endpoints exist in the UI."""
    assert dash_path.exists(), f"Dashboard file {dash_path} must exist"
    content = dash_path.read_text(encoding="utf-8")
    static_root = NETOPS_HOME / "src" / "netops_guardrail" / "observability" / "static"
    assets = content
    for asset in (static_root / "css" / "dashboard.css", static_root / "js" / "dashboard.js"):
        if asset.exists():
            assets += asset.read_text(encoding="utf-8")
    for banned in BANNED_STRINGS:
        assert banned not in assets, (
            f"Banned string '{banned}' was found in {dash_path}. "
            f"Simulated UI elements must be completely removed."
        )


@pytest.mark.parametrize("dash_path", DASHBOARD_PATHS)
def test_required_dashboard_elements_present(dash_path: Path):
    """Verify presence of preflight indicators, timeline container, tokens, and audit display."""
    content = dash_path.read_text(encoding="utf-8")
    for elem_id in REQUIRED_ELEMENT_IDS:
        pattern = f'id="{elem_id}"'
        assert pattern in content, f"Required element '{elem_id}' missing in {dash_path}"

    assert "Invariant-based runtime verification" in content, (
        f"Product name 'Invariant-based runtime verification' missing in {dash_path}"
    )


@pytest.mark.parametrize("dash_path", DASHBOARD_PATHS)
def test_no_web_storage(dash_path: Path):
    """Fail on ANY occurrence of localStorage or sessionStorage in the dashboard source."""
    assert dash_path.exists(), f"Dashboard file {dash_path} must exist"
    content = dash_path.read_text(encoding="utf-8")
    static_js = (
        NETOPS_HOME
        / "src"
        / "netops_guardrail"
        / "observability"
        / "static"
        / "js"
        / "dashboard.js"
    )
    if static_js.exists():
        content += static_js.read_text(encoding="utf-8")
    assert "localStorage" not in content, (
        f"Prohibited 'localStorage' found in dashboard source: {dash_path}"
    )
    assert "sessionStorage" not in content, (
        f"Prohibited 'sessionStorage' found in dashboard source: {dash_path}"
    )


def test_api_pipeline_preflight_and_restore_workflow(monkeypatch, tmp_path):
    """Test full preflight checks and guarded baseline restore via API."""
    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(
        json.dumps(
            {
                "updated_at_utc": datetime.now(timezone.utc).isoformat(),
                "switches": {"1": {}, "2": {}},
            }
        ),
        encoding="utf-8",
    )

    incident_dir = tmp_path / "incidents"
    incident_dir.mkdir(parents=True, exist_ok=True)
    monitor_path = incident_dir / "monitor_status.json"
    monitor_path.write_text(
        json.dumps(
            {
                "status": "running",
                "last_heartbeat_utc": datetime.now(timezone.utc).isoformat(),
                "interval_seconds": 5,
            }
        ),
        encoding="utf-8",
    )

    runs_dir = tmp_path / "runs"
    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "operator-secret-999")

    executed = []

    def mock_run_cmd(cmd, **kwargs):
        executed.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    app = create_metrics_app(telemetry_path=str(telemetry_path))
    app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(runs_dir)
    app.config["NETOPS_MONITOR_STATUS_PATH"] = str(monitor_path)
    app.config["NETOPS_CONNECTIVITY_CHECKER_OVERRIDE"] = lambda: True
    app.config["NETOPS_RUN_COMMAND_OVERRIDE"] = mock_run_cmd

    client = app.test_client()

    # Preflight OK
    res_pf = client.get("/api/pipeline/preflight")
    assert res_pf.status_code == 200
    pf_data = res_pf.get_json()
    assert pf_data["ready"] is True
    assert pf_data["token_configured"] is True
    assert pf_data["telemetry"]["status"] == "ok"
    assert pf_data["monitor_heartbeat"]["status"] == "ok"
    assert pf_data["baseline_connectivity"]["status"] == "passed"

    # Preflight fails when telemetry becomes stale
    telemetry_path.write_text(
        json.dumps(
            {
                "updated_at_utc": "2020-01-01T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    res_pf_stale = client.get("/api/pipeline/preflight")
    assert res_pf_stale.get_json()["ready"] is False
    assert res_pf_stale.get_json()["telemetry"]["status"] == "stale"

    # Restore endpoint requires token
    res_unauth = client.post("/api/pipeline/restore")
    assert res_unauth.status_code == 401

    # Restore endpoint succeeds with Authorization header Bearer token
    res_restore = client.post(
        "/api/pipeline/restore",
        headers={"Authorization": "Bearer operator-secret-999"},
    )
    assert res_restore.status_code == 200
    res_data = res_restore.get_json()
    assert res_data["success"] is True
    assert len(res_data["completed_commands"]) == 10
    assert len(executed) == 10

    # Faults metadata endpoint
    res_faults = client.get("/api/pipeline/faults")
    assert res_faults.status_code == 200
    faults = res_faults.get_json()["faults"]
    assert len(faults) == 4
    assert "mac_flooding" not in {fault["id"] for fault in faults}
    for fault in faults:
        assert "id" in fault
        assert "target" in fault
        assert "commands" in fault
        assert isinstance(fault["commands"], list)


@pytest.mark.parametrize("dash_path", DASHBOARD_PATHS)
def test_responsive_layout_and_css_rules(dash_path: Path):
    """HTML/CSS smoke test verifying responsive breakpoints at 1280px and 768px/360px."""
    content = dash_path.read_text(encoding="utf-8")
    css_path = (
        NETOPS_HOME
        / "src"
        / "netops_guardrail"
        / "observability"
        / "static"
        / "css"
        / "dashboard.css"
    )
    if css_path.exists():
        content += css_path.read_text(encoding="utf-8")
    # Verify main grid definition
    assert "grid-template-columns:" in content
    # Verify responsive break points for >=1280px, <1280px (tablet), and <768px (mobile)
    assert "@media (max-width: 1279px)" in content or "@media (max-width: 1280px)" in content
    assert "@media (max-width: 767px)" in content or "@media (max-width: 768px)" in content
    # Verify horizontal scroll prevention
    assert "overflow-x: hidden" in content or "overflow-x:hidden" in content
    # Verify vis.js canvas container and viewport
    assert 'id="topology-canvas"' in content
    assert 'class="topology-viewport"' in content or 'id="topology-viewport"' in content
