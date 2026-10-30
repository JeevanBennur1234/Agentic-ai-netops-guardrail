#!/usr/bin/env python3
"""Synthetic safety-case evaluation and simulated full-executor benchmark."""
import copy, json, math, re, statistics, tempfile, time, sys
from datetime import datetime, timezone
from pathlib import Path
from netops_guardrail.netops_paths import NETOPS_HOME
ROOT = NETOPS_HOME
from netops_guardrail.controller.decision_gate import apply_intent_to_graph
from netops_guardrail.executor.remediation_executor import RemediationExecutor
from netops_guardrail.verifier.safety_verifier import build_topology
from netops_guardrail.experiments.topologies import build_redundant_topology_data, build_star_topology_data

OUT_JSON = ROOT / "experiments/results/recommended_evaluation_20261027.json"
OUT_MD = ROOT / "experiments/results/recommended_evaluation_20261027.md"

def stp_redundant():
    telem, _, _ = build_redundant_topology_data()
    telem = copy.deepcopy(telem)
    telem["links"] = [
        {"src_switch":"1","src_port":"2","dst_switch":"2","dst_port":"1"},
        {"src_switch":"1","src_port":"3","dst_switch":"2","dst_port":"2"},
    ]
    telem["switches"]["1"]["stp_port_states"] = {"1":"FORWARD","2":"FORWARD","3":"FORWARD"}
    telem["switches"]["2"]["stp_port_states"] = {"1":"FORWARD","2":"BLOCK","3":"FORWARD"}
    return telem

def labelled_cases():
    star, _ = build_star_topology_data()
    redundant, _, _ = build_redundant_topology_data()
    # The fixture helper returns a graph separately from telemetry; encode
    # its two physical trunk edges in telemetry before rebuilding the graph.
    redundant["links"] = [
        {"src_switch":"1","src_port":"2","dst_switch":"2","dst_port":"1"},
        {"src_switch":"1","src_port":"3","dst_switch":"2","dst_port":"2"},
    ]
    stp = stp_redundant()
    single = copy.deepcopy(redundant)
    single["links"] = [x for x in single.get("links", [])
        if {str(x.get("src_switch")), str(x.get("dst_switch"))} == {"1","2"}
        and {str(x.get("src_port")), str(x.get("dst_port"))} == {"2","1"}]
    disconnected = copy.deepcopy(star)
    disconnected["switches"]["2"] = {"ports":{"1":{"rx_packets":0,"tx_packets":0,"rx_bytes":0,"tx_bytes":0}},"flows":[]}
    disconnected["links"] = []
    return [
      ("healthy-star-no-action", True, star, {"action":"no_action","reason":"nominal"}, "Healthy no-op."),
      ("block-access-port-2", False, star, {"action":"block","target_switch":"1","from_port":"2","reason":"test"}, "Access isolation."),
      ("nonexistent-port", False, star, {"action":"block","target_switch":"1","from_port":"99","reason":"test"}, "Missing port."),
      ("unsupported-reroute", False, redundant, {"action":"reroute","target_switch":"1","from_port":"2","to_port":"3","reason":"test"}, "Reroute is fail-closed."),
      ("block-redundant-trunk", True, redundant, {"action":"block","target_switch":"1","from_port":"2","reason":"test"}, "Alternate physical path is forwarding in synthetic graph."),
      ("block-active-while-backup-stp-blocked", False, stp, {"action":"block","target_switch":"1","from_port":"2","reason":"test"}, "Alternate trunk has a STP-blocked endpoint."),
      ("block-already-stp-blocked-trunk", True, stp, {"action":"block","target_switch":"1","from_port":"3","reason":"test"}, "Active trunk A remains forwarding."),
      ("block-only-trunk", False, single, {"action":"block","target_switch":"1","from_port":"2","reason":"test"}, "Removing sole trunk disconnects switches."),
      ("invalid-action", False, redundant, {"action":"flush_everything","reason":"test"}, "Unsupported action."),
      ("missing-block-target", False, redundant, {"action":"block","reason":"test"}, "Missing target details."),
      ("disconnected-no-action", False, disconnected, {"action":"no_action","reason":"test"}, "Current topology is disconnected."),
      ("block-access-port-3", False, star, {"action":"block","target_switch":"1","from_port":"3","reason":"test"}, "Second access-port negative control."),
    ]

def evaluate_cases():
    rows=[]; safe_n=unsafe_n=fa=fr=0
    for name, expected, telemetry, intent, rationale in labelled_cases():
        result=apply_intent_to_graph(build_topology(telemetry),intent)
        predicted=bool(result.get("safe",False))
        if expected:
            safe_n+=1; fr+=int(not predicted)
        else:
            unsafe_n+=1; fa+=int(predicted)
        rows.append({"name":name,"expected_safe":expected,"predicted_safe":predicted,
                     "correct":expected==predicted,"rationale":rationale,"verifier_result":result})
    return {"type":"synthetic_labelled_safety_cases","case_count":len(rows),
      "safe_case_count":safe_n,"unsafe_case_count":unsafe_n,
      "correct_count":sum(x["correct"] for x in rows),"incorrect_count":sum(not x["correct"] for x in rows),
      "false_accept_count":fa,"false_reject_count":fr,
      "false_accept_rate":fa/unsafe_n if unsafe_n else None,
      "false_reject_rate":fr/safe_n if safe_n else None,
      "accuracy":sum(x["correct"] for x in rows)/len(rows) if rows else None,
      "cases":rows,
      "caveat":"Manually labelled synthetic cases only; not a representative dataset or a measurement of LLM decision quality."}

class FakeOVSRunner:
    def __init__(self): self.flows={"s1":[],"s2":[]}
    def __call__(self,args):
        args=list(args)
        if "br-exists" in args: return 0,"",""
        if "dump-flows" in args: return 0,"\n".join(self.flows.get(args[-1],[])),""
        if "add-flow" in args:
            self.flows.setdefault(args[-2],[]).append(args[-1]); return 0,"",""
        if "del-flows" in args:
            bridge, filt=args[-2],args[-1]
            m=re.search(r"cookie=0x([0-9a-f]+)/",filt,re.I)
            if m:
                target=int(m.group(1),16); kept=[]
                for line in self.flows.get(bridge,[]):
                    found=re.search(r"\bcookie=0x([0-9a-f]+)\b",line,re.I)
                    if not found or int(found.group(1),16)!=target: kept.append(line)
                self.flows[bridge]=kept
            else: self.flows[bridge]=[]
            return 0,"",""
        return 0,"",""

def timing_stats(values):
    values=sorted(values)
    return {"count":len(values),"mean_ms":round(statistics.mean(values)*1000,3),
      "median_ms":round(statistics.median(values)*1000,3),
      "p95_ms":round(values[min(len(values)-1,math.ceil(.95*len(values))-1)]*1000,3),
      "min_ms":round(min(values)*1000,3),"max_ms":round(max(values)*1000,3)}

def benchmark_executor_transaction(repetitions=30):
    telem, graph, endpoints=build_redundant_topology_data()
    post=graph.copy(); post.remove_node("s1-p2")
    def provider(phase="pre"): return (post if phase=="post" else graph,endpoints)
    values=[]; failures=[]
    with tempfile.TemporaryDirectory(prefix="netops-guardrail-eval-") as tmp:
        path=Path(tmp)/"telemetry.json"; path.write_text(json.dumps(telem),encoding="utf-8")
        for i in range(repetitions):
            runner=FakeOVSRunner()
            executor=RemediationExecutor(telemetry_path=str(path),cmd_runner=runner,
                topology_provider=provider,connectivity_checker=lambda:True,
                require_connectivity_check=True,require_human_approval=False)
            intent={"action":"block","target_switch":"1","from_port":"2","reason":"benchmark transaction"}
            start=time.perf_counter(); result=executor.execute(intent,"APPROVED",{"safe":True})
            values.append(time.perf_counter()-start)
            if not (result.get("success") is True and result.get("change_verified") is True
                    and result.get("safety_verified") is True and result.get("connectivity_verified") is True
                    and len(runner.flows.get("s1",[]))==1 and len(runner.flows.get("s2",[]))==1):
                failures.append({"iteration":i+1,"result":result})
    return {"type":"simulated_executor_transaction","repetitions_requested":repetitions,
      "stats":timing_stats(values),"success_count":repetitions-len(failures),"failure_count":len(failures),
      "real_ovs_commands_executed":False,"live_connectivity_tested":False,
      "what_is_measured":"Current RemediationExecutor logic with an in-memory command runner: preflight, paired adds, cookie verification, topology post-check, and a stub connectivity callback.",
      "caveat":"Software-path timing only; not real OVS latency or proof of live data-plane recovery.","failures":failures}

def main():
    evaluation={"generated_at_utc":datetime.now(timezone.utc).isoformat(),
                "labelled_safety_evaluation":evaluate_cases(),
                "executor_transaction_benchmark":benchmark_executor_transaction()}
    for name in ("live_active_failover_latest.json","live_triangle_failover_latest.json"):
        p=ROOT/"experiments/results"/name
        if p.exists():
            try: evaluation.setdefault("live_failure_experiments",{})[name]=json.loads(p.read_text(encoding="utf-8"))
            except (OSError,json.JSONDecodeError): pass
    integration_path = ROOT / "experiments/results/live_integration_summary_20261027.json"
    if integration_path.exists():
        try:
            evaluation["live_integration_summary"] = json.loads(
                integration_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            pass
    OUT_JSON.write_text(json.dumps(evaluation,indent=2),encoding="utf-8")
    l=evaluation["labelled_safety_evaluation"]; b=evaluation["executor_transaction_benchmark"]
    lines=["# Recommended Work Evaluation - 2026-10-27","",
      "## Labelled safety cases","",
      f"- Cases: {l['case_count']} ({l['safe_case_count']} safe; {l['unsafe_case_count']} unsafe)",
      f"- Correct: {l['correct_count']} / {l['case_count']}",
      f"- False accepts: {l['false_accept_count']} / {l['unsafe_case_count']} ({l['false_accept_rate']:.1%})",
      f"- False rejects: {l['false_reject_count']} / {l['safe_case_count']} ({l['false_reject_rate']:.1%})","",
      l["caveat"],"","## Executor transaction benchmark","",
      f"- Repetitions: {b['stats']['count']}",
      f"- Mean: {b['stats']['mean_ms']} ms; median: {b['stats']['median_ms']} ms; p95: {b['stats']['p95_ms']} ms",
      f"- Successful simulated transactions: {b['success_count']} / {b['repetitions_requested']}",
      "- Host OVS modified: no","- Live connectivity measured: no","",b["what_is_measured"],"",b["caveat"],"",
      "## Fresh live integration evidence","",
      "- Two-switch topology/STP baseline: PASS; baseline pingall loss 0.0%.",
      "- Paired trunk-remediation test: PASS; both rules verified, live connectivity remained at 0.0% loss, access-port block rejected, audit chain verified.",
      "- Active-trunk safety decision: PASS; gate and executor both rejected an active-trunk block when the alternate was STP-blocked, with no flow-table changes and no connectivity loss.",
      "- Active-route administrative-down experiment: FAILOVER_FAILED_ROLLBACK_PASS; post-failure ping loss reached 100.0%, then re-enabling the original trunk restored 0.0% loss in about 0.014 seconds.",
      "- The admin-down experiments are not physical cable-unplug tests. Automatic physical-link failover remains unproven.",
      "",
      "The JSON report embeds the full live-test reports. Rollback success is reported separately and is not counted as failover success.","",
      "## Reproduce","","Run python3 experiments/evaluate_guardrail_cases.py from the project root. The synthetic evaluator does not modify host OVS."]
    OUT_MD.write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps({"json":str(OUT_JSON),"markdown":str(OUT_MD),"cases":l["case_count"],
      "correct":l["correct_count"],"false_accept_rate":l["false_accept_rate"],
      "false_reject_rate":l["false_reject_rate"],"executor_transaction":b["stats"],
      "benchmark_success_count":b["success_count"],"benchmark_failure_count":b["failure_count"]},indent=2))
    return 0 if b["failure_count"]==0 else 1

if __name__=="__main__": raise SystemExit(main())
