import hashlib
from pathlib import Path

import pytest

from remediation_service import build_parser, load_callable, telemetry_fingerprint


def test_service_is_dry_run_by_default():
    args = build_parser().parse_args([])
    assert args.execute is False
    assert args.connectivity_checker is None


def test_service_fingerprint_tracks_exact_telemetry_bytes(tmp_path):
    sample = tmp_path / "latest.json"
    sample.write_text('{"switches":{}}', encoding="utf-8")
    expected = hashlib.sha256(sample.read_bytes()).hexdigest()
    assert telemetry_fingerprint(str(sample)) == expected


def test_service_fingerprint_changes_when_telemetry_changes(tmp_path):
    sample = tmp_path / "latest.json"
    sample.write_text('{"switches":{}}', encoding="utf-8")
    before = telemetry_fingerprint(str(sample))
    sample.write_text('{"switches":{"1":{}}}', encoding="utf-8")
    after = telemetry_fingerprint(str(sample))
    assert before != after


def test_service_loads_callable_by_module_and_attribute():
    import math
    assert load_callable("math:sqrt") is math.sqrt


def test_service_rejects_invalid_callable_spec():
    with pytest.raises(ValueError):
        load_callable("math")


def test_service_once_invokes_decision_pipeline_in_dry_run(monkeypatch, tmp_path, capsys):
    import remediation_service as service

    telemetry = tmp_path / "latest.json"
    telemetry.write_text('{"switches":{}}', encoding="utf-8")
    captured = {}

    def fake_decide(**kwargs):
        captured.update(kwargs)
        return {"decision": "REJECTED", "execution": None}

    monkeypatch.setattr(service, "decide", fake_decide)
    code = service.run(["--telemetry", str(telemetry), "--once"])
    assert code == 0
    assert captured["telemetry_path"] == str(telemetry)
    assert captured["execute_approved"] is False
    assert captured["connectivity_checker"] is None
    assert "dry-run" in capsys.readouterr().out


def test_service_execute_mode_requires_connectivity_checker(tmp_path):
    import remediation_service as service

    telemetry = tmp_path / "latest.json"
    telemetry.write_text('{"switches":{}}', encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        service.run(["--telemetry", str(telemetry), "--once", "--execute"])
    assert exc.value.code == 2


def test_service_reports_failed_executor_result(monkeypatch, tmp_path):
    import remediation_service as service

    telemetry = tmp_path / "latest.json"
    telemetry.write_text('{"switches":{}}', encoding="utf-8")
    monkeypatch.setattr(
        service,
        "decide",
        lambda **kwargs: {"decision": "APPROVED", "execution": {"success": False}},
    )
    assert service.run(["--telemetry", str(telemetry), "--once"]) == 1
