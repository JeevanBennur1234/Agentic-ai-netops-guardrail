#!/usr/bin/env python3
"""Capture responsive UI screenshots across scenarios and viewports using Playwright."""

import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from netops_guardrail.controller.human_verifier import HumanApprovalStore
from netops_guardrail.controller.pipeline_run import PipelineRun, PipelineRunManager
from netops_guardrail.observability.server import create_metrics_app

OUTPUT_DIR = REPO_ROOT / "experiments" / "results" / "ui"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

VIEWPORTS = [
    {"name": "360", "width": 360, "height": 740},
    {"name": "768", "width": 768, "height": 1024},
    {"name": "1280", "width": 1280, "height": 800},
]


def make_fixture_telemetry(stale: bool = False) -> dict:
    if stale:
        timestamp = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    else:
        timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "fixture_telemetry": True,
        "fixture_mode": True,
        "fixture_label": "TEST FIXTURE TELEMETRY - NOT LIVE NETWORK",
        "updated_at_utc": timestamp,
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
        "switches": {
            "1": {
                "dpid": "1",
                "ports": {
                    "1": {
                        "rx_packets": 240,
                        "tx_packets": 255,
                        "rx_bytes": 18400,
                        "tx_bytes": 19200,
                    },
                    "2": {
                        "rx_packets": 1150,
                        "tx_packets": 1120,
                        "rx_bytes": 98200,
                        "tx_bytes": 94100,
                    },
                    "3": {"rx_packets": 12, "tx_packets": 8, "rx_bytes": 960, "tx_bytes": 640},
                },
                "flows": [
                    {"priority": 1, "packet_count": 120, "byte_count": 9600},
                    {"priority": 0, "packet_count": 450, "byte_count": 32000},
                ],
                "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"},
                "port_status": {
                    "1": {"state": "UP"},
                    "2": {"state": "UP"},
                    "3": {"state": "UP"},
                },
            },
            "2": {
                "dpid": "2",
                "ports": {
                    "1": {
                        "rx_packets": 1120,
                        "tx_packets": 1150,
                        "rx_bytes": 94100,
                        "tx_bytes": 98200,
                    },
                    "2": {"rx_packets": 8, "tx_packets": 12, "rx_bytes": 640, "tx_bytes": 960},
                    "3": {
                        "rx_packets": 255,
                        "tx_packets": 240,
                        "rx_bytes": 19200,
                        "tx_bytes": 18400,
                    },
                },
                "flows": [
                    {"priority": 1, "packet_count": 118, "byte_count": 9440},
                    {"priority": 0, "packet_count": 442, "byte_count": 31400},
                ],
                "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"},
                "port_status": {
                    "1": {"state": "UP"},
                    "2": {"state": "UP"},
                    "3": {"state": "UP"},
                },
            },
        },
    }


class ServerThread(threading.Thread):
    def __init__(self, app, host="127.0.0.1", port=8765):
        super().__init__()
        self.server = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


def inspect_page_layout(page, scenario: str, width: int) -> list[str]:
    """Inspect DOM for horizontal overflow, overlapping cards, or clipped elements."""
    issues = []
    # Check body horizontal scroll/overflow
    overflow = page.evaluate("""() => {
        const body = document.body;
        const html = document.documentElement;
        const scrollW = Math.max(body.scrollWidth, html.scrollWidth);
        const clientW = html.clientWidth;
        return {
            hasOverflow: scrollW > clientW + 2,
            scrollWidth: scrollW,
            clientWidth: clientW,
        };
    }""")
    if overflow["hasOverflow"]:
        issues.append(
            f"Horizontal overflow detected at {width}px: scrollWidth={overflow['scrollWidth']}px > clientWidth={overflow['clientWidth']}px"
        )

    # Check independent card surfaces for geometric overlap. Nested children are
    # excluded so normal card content does not produce false positives.
    overlaps = page.evaluate("""() => {
        const selectors = '.card, .panel, .metric-card, .dashboard-card, .section-card';
        const cards = [...document.querySelectorAll(selectors)]
            .filter(el => el.offsetParent !== null)
            .filter(el => ![...el.parentElement?.closest(selectors) ? [el.parentElement.closest(selectors)] : []].length);
        const found = [];
        for (let i = 0; i < cards.length; i++) {
            const a = cards[i].getBoundingClientRect();
            for (let j = i + 1; j < cards.length; j++) {
                const b = cards[j].getBoundingClientRect();
                const overlapW = Math.min(a.right, b.right) - Math.max(a.left, b.left);
                const overlapH = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
                if (overlapW > 2 && overlapH > 2) {
                    found.push({
                        first: cards[i].id || cards[i].className,
                        second: cards[j].id || cards[j].className,
                        overlapWidth: Math.round(overlapW),
                        overlapHeight: Math.round(overlapH),
                    });
                }
            }
        }
        return found;
    }""")
    for overlap in overlaps:
        issues.append(
            f"Overlapping cards at {width}px: {overlap['first']} and {overlap['second']} "
            f"({overlap['overlapWidth']}x{overlap['overlapHeight']}px intersection)"
        )

    # Check for text clipping in key headers and badges
    clipped_elements = page.evaluate("""() => {
        const elements = document.querySelectorAll('.card-title, .badge, .status-pill, button');
        const clipped = [];
        for (const el of elements) {
            if (el.scrollWidth > el.clientWidth + 4 && el.clientWidth > 0) {
                clipped.push({
                    text: el.innerText.trim().slice(0, 30),
                    tag: el.tagName,
                    id: el.id,
                    className: el.className,
                    scrollWidth: el.scrollWidth,
                    clientWidth: el.clientWidth,
                });
            }
        }
        return clipped;
    }""")
    for el in clipped_elements:
        issues.append(
            f"Clipped label at {width}px: <{el['tag']} id='{el['id']}'> '{el['text']}' (scrollWidth {el['scrollWidth']}px > clientWidth {el['clientWidth']}px)"
        )

    return issues


def run_scenario(scenario_name: str, app_setup_fn, browser, report: dict):
    print(f"\n--- Scenario: {scenario_name} ---")
    tmp_dir = REPO_ROOT / "observability" / "data" / "fixture_tmp" / scenario_name
    tmp_dir.mkdir(parents=True, exist_ok=True)

    app = app_setup_fn(tmp_dir)
    server = ServerThread(app, port=8765)
    server.start()
    time.sleep(0.5)

    try:
        for vp in VIEWPORTS:
            w, h = vp["width"], vp["height"]
            vp_name = vp["name"]
            out_file = OUTPUT_DIR / f"{scenario_name}_{vp_name}.png"

            context = browser.new_context(viewport={"width": w, "height": h})
            page = context.new_page()
            page_errors = []
            page.on("pageerror", lambda error: page_errors.append(str(error)))

            # Navigate to dashboard
            page.goto("http://127.0.0.1:8765/dashboard", wait_until="networkidle", timeout=10000)
            time.sleep(0.8)  # Allow vis.js physics and polling to settle

            # Take screenshot
            page.screenshot(path=str(out_file), full_page=True)
            print(f"  [SAVED] {out_file.name} ({w}x{h})")

            # Check layout issues
            issues = inspect_page_layout(page, scenario_name, w)
            issues.extend(f"Browser JavaScript error: {error}" for error in page_errors)
            if issues:
                print(f"  [WARN] {len(issues)} layout notice(s) at {w}px:")
                for iss in issues:
                    print(f"    - {iss}")
                report.setdefault(scenario_name, {})[vp_name] = issues
            else:
                print(f"  [OK] No overflow or clipped labels at {w}px.")
                report.setdefault(scenario_name, {})[vp_name] = []

            context.close()
    finally:
        server.shutdown()
        server.join()


def main():
    report = {}
    os.environ["NETOPS_CHAOS_API_TOKEN"] = "fixture-secret-token"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # 1. Idle scenario
        def setup_idle(tmp_dir):
            telem_path = tmp_dir / "latest.json"
            telem_path.write_text(json.dumps(make_fixture_telemetry(stale=False)), encoding="utf-8")
            runs_dir = tmp_dir / "runs"
            runs_dir.mkdir(parents=True, exist_ok=True)
            app = create_metrics_app(telemetry_path=str(telem_path))
            app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(runs_dir)
            return app

        run_scenario("idle", setup_idle, browser, report)

        # 2. Run in progress scenario
        def setup_run_in_progress(tmp_dir):
            telem_path = tmp_dir / "latest.json"
            telem_path.write_text(json.dumps(make_fixture_telemetry(stale=False)), encoding="utf-8")
            runs_dir = tmp_dir / "runs"
            mgr = PipelineRunManager(runs_dir)
            run = PipelineRun(
                run_id="run-progress-fixture", fault_id="redundant_trunk_restored", executable=True
            )
            run.start_stage(
                "fault_injected", evidence={"fault": "redundant_trunk_restored", "fixture": True}
            )
            run.complete_stage("fault_injected")
            run.start_stage("telemetry_observed", evidence={"links_observed": 2})
            run.complete_stage("telemetry_observed")
            run.start_stage("detected", evidence={"anomaly": "redundant_trunk_up"})
            run.complete_stage("detected")
            run.start_stage(
                "ai_analysis", evidence={"model": "qwen2.5-coder:1.5b", "evaluating": True}
            )
            mgr.save_run(run)

            app = create_metrics_app(telemetry_path=str(telem_path))
            app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(runs_dir)
            return app

        run_scenario("run_in_progress", setup_run_in_progress, browser, report)

        # 3. Awaiting approval scenario
        def setup_awaiting_approval(tmp_dir):
            telem_path = tmp_dir / "latest.json"
            telem_path.write_text(json.dumps(make_fixture_telemetry(stale=False)), encoding="utf-8")
            runs_dir = tmp_dir / "runs"
            approval_file = tmp_dir / "proposals.json"
            store = HumanApprovalStore(path=str(approval_file))

            proposal = store.create_proposal(
                intent={
                    "action": "block",
                    "target_switch": "1",
                    "from_port": "3",
                    "reason": "FIXTURE: Telemetry reveals redundant standby trunk in forwarding state creating loop risk.",
                    "confidence": 0.95,
                },
                verifier_result={
                    "safe": True,
                    "details": "Verified loop-free after proposed block",
                },
                telemetry_path=str(telem_path),
                requested_by="continuous-monitor",
            )
            prop_id = proposal.get("proposal_id", "fixture-prop-1")

            mgr = PipelineRunManager(runs_dir)
            run = PipelineRun(
                run_id="run-await-fixture",
                fault_id="redundant_trunk_restored",
                executable=True,
                proposal_id=prop_id,
            )
            run.complete_stage("fault_injected")
            run.complete_stage("telemetry_observed")
            run.complete_stage("detected")
            run.complete_stage("ai_analysis", evidence={"proposal": proposal["intent"]})
            run.complete_stage("safety_verified", evidence={"safe": True})
            run.start_stage("awaiting_approval", evidence={"proposal_id": prop_id})
            run.status = "AWAITING_APPROVAL"
            mgr.save_run(run)

            app = create_metrics_app(
                telemetry_path=str(telem_path), approval_path=str(approval_file)
            )
            app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(runs_dir)
            return app

        run_scenario("awaiting_approval", setup_awaiting_approval, browser, report)

        # 4. Stale telemetry scenario
        def setup_stale_telemetry(tmp_dir):
            telem_path = tmp_dir / "latest.json"
            telem_path.write_text(json.dumps(make_fixture_telemetry(stale=True)), encoding="utf-8")
            runs_dir = tmp_dir / "runs"
            runs_dir.mkdir(parents=True, exist_ok=True)
            app = create_metrics_app(telemetry_path=str(telem_path))
            app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(runs_dir)
            return app

        run_scenario("stale_telemetry", setup_stale_telemetry, browser, report)

        browser.close()

    print("\n================== SUMMARY REPORT ==================")
    report_file = OUTPUT_DIR / "layout_inspection_report.json"
    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Layout report saved to: {report_file}")
    for scen, vps in report.items():
        for vp, issues in vps.items():
            status = "PASSED" if not issues else f"{len(issues)} issues"
            print(f"  {scen} @ {vp}px: {status}")


if __name__ == "__main__":
    main()
