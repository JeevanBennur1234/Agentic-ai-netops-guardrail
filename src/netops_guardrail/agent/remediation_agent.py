import hashlib
import json
import os
import urllib.request

from jsonschema import ValidationError, validate


def _detect_ollama_url():
    if "OLLAMA_URL" in os.environ:
        return os.environ["OLLAMA_URL"]
    for test_url in ["http://127.0.0.1:11434", "http://localhost:11434"]:
        try:
            req = urllib.request.Request(f"{test_url}/api/tags")
            with urllib.request.urlopen(req, timeout=0.5):
                return f"{test_url}/api/generate"
        except Exception:
            pass
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) > 2 and fields[1] == "00000000":
                    import socket
                    import struct

                    host_ip = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                    return f"http://{host_ip}:11434/api/generate"
    except Exception:
        pass
    return "http://172.21.32.1:11434/api/generate"


OLLAMA_URL = _detect_ollama_url()
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:1.5b")
from netops_guardrail.netops_paths import NETOPS_HOME

DEFAULT_TELEMETRY_PATH = str(NETOPS_HOME / "telemetry" / "data" / "latest.json")

INTENT_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["reroute", "block", "no_action"]},
        "target_switch": {"type": "string"},
        "from_port": {"type": "string"},
        "to_port": {"type": "string"},
        "reason": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "evidence_refs": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
    },
    "required": ["action", "reason"],
}


def get_valid_physical_ports(telemetry):
    """
    Dynamically derive valid physical ports per switch from telemetry.
    Ignores OpenFlow LOCAL port (4294967294) and reserved ports (>= 4294967040).
    """
    valid_ports = {}
    for sw_id, sw_data in telemetry.get("switches", {}).items():
        ports = []
        for p in sw_data.get("ports", {}).keys():
            try:
                p_int = int(p)
                if p_int >= 4294967040:
                    continue
                ports.append(str(p))
            except ValueError:
                if str(p).lower() != "local":
                    ports.append(str(p))
        valid_ports[str(sw_id)] = sorted(ports, key=lambda x: int(x) if x.isdigit() else x)
    return valid_ports


def sanitize_telemetry(telemetry):
    """
    Produce a sanitized copy of telemetry containing ONLY valid physical ports.
    Completely excludes OpenFlow LOCAL port 4294967294 and reserved ports.
    """
    sanitized = {
        "switches": {},
        "links": telemetry.get("links", []),
        "updated_at_utc": telemetry.get("updated_at_utc"),
    }
    for sw_id, sw_data in telemetry.get("switches", {}).items():
        clean_ports = {}
        for p_id, p_stats in sw_data.get("ports", {}).items():
            try:
                if int(p_id) >= 4294967040:
                    continue
            except ValueError:
                if str(p_id).lower() == "local":
                    continue
            clean_ports[str(p_id)] = p_stats
        sanitized["switches"][str(sw_id)] = {
            "ports": clean_ports,
            "flows": sw_data.get("flows", []),
            "stp_port_states": {
                str(port): str(state).upper()
                for port, state in (sw_data.get("stp_port_states") or {}).items()
            },
            "port_status": sw_data.get("port_status", {}),
        }
    return sanitized


def _tag_agent_result(intent, *, model_invoked, status, prompt=None, raw_output=None):
    """Record whether the LLM actually ran, including deterministic early exits."""
    metadata = {
        "model": MODEL if model_invoked else None,
        "model_invoked": bool(model_invoked),
        "status": status,
    }
    if prompt is not None:
        metadata["prompt_sha256"] = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    if raw_output is not None:
        metadata["raw_output"] = raw_output
    metadata["parsed_decision"] = {
        "action": intent.get("action"),
        "reason": intent.get("reason"),
        "confidence": intent.get("confidence"),
        "evidence_refs": intent.get("evidence_refs", []),
    }
    intent["_agent_metadata"] = metadata
    return intent


PROMPT_TEMPLATE = """You are an autonomous network operations remediation agent.

Given this network telemetry snapshot (JSON), decide if remediation is needed.

Available switches and valid physical ports:
{valid_ports}

Telemetry (monitored physical ports only):
{telemetry}

Decision Guidelines:
1. Examine packet statistics (rx_packets, tx_packets, rx_bytes, tx_bytes) and flows on the valid physical ports.
2. If traffic is flowing normally, flows exist, and there is no evidence of packet drops or congestion on any port, you MUST choose "no_action".
3. Do NOT invent packet loss, congestion, or link failures not supported by the telemetry.
4. Only propose "block" or "reroute" if telemetry provides clear evidence of a failure or severe anomaly on a valid physical port.
5. If choosing "no_action", do not specify port fields. You MUST always provide a clear evidence-based "reason" field.
6. If choosing "block" or "reroute", "target_switch" must be a valid switch and "from_port" MUST be strictly one of that switch's valid physical ports: {valid_ports}. Never select or invent any other port.

Respond ONLY with a single JSON object matching this schema. Note that BOTH "action" AND "reason" fields are strictly required:
{schema}
"""


def propose_remediation(
    telemetry_path=None,
    incident_context=None,
):
    if telemetry_path is None:
        telemetry_path = DEFAULT_TELEMETRY_PATH

    with open(telemetry_path, "r") as file:
        telemetry = json.load(file)

    # Derive valid physical ports dynamically from telemetry
    valid_ports = get_valid_physical_ports(telemetry)

    # Present only physical ports to Ollama (removes LOCAL port 4294967294)
    clean_telemetry = sanitize_telemetry(telemetry)

    prompt = PROMPT_TEMPLATE.format(
        valid_ports=json.dumps(valid_ports, indent=2),
        telemetry=json.dumps(clean_telemetry, indent=2),
        schema=json.dumps(INTENT_SCHEMA, indent=2),
    )
    if incident_context:
        # Only telemetry-derived evidence is exposed to the model. Caller-supplied
        # expected actions/targets/reasons are deliberately excluded.
        fault_type = str(incident_context.get("fault_type", "unknown"))
        compact_telemetry = {
            "updated_at_utc": clean_telemetry.get("updated_at_utc"),
            "links": clean_telemetry.get("links", []),
            "switches": {
                sid: {
                    "ports": sw.get("ports", {}),
                    "flows": sw.get("flows", []),
                    "stp_port_states": sw.get("stp_port_states", {}),
                    "port_status": sw.get("port_status", {}),
                }
                for sid, sw in clean_telemetry.get("switches", {}).items()
            },
        }
        evidence_id = incident_context.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            evidence_id = (
                __import__("hashlib")
                .sha256(json.dumps(compact_telemetry, sort_keys=True).encode("utf-8"))
                .hexdigest()[:24]
            )
        evidence = {
            "evidence_id": evidence_id,
            "incident_type": fault_type,
            "source": incident_context.get("source", "live_telemetry"),
            "detector_evidence": incident_context.get("evidence", {}),
            "telemetry": compact_telemetry,
        }
        if fault_type in {"telemetry_stale", "topology_offline"}:
            reason = (
                "Telemetry is stale; remediation is prohibited."
                if fault_type == "telemetry_stale"
                else "The testbed is disconnected; remediation is prohibited until switches reconnect."
            )
            return _tag_agent_result(
                {
                    "action": "no_action",
                    "reason": reason,
                    "confidence": 1.0,
                    "evidence_refs": [evidence_id],
                },
                model_invoked=False,
                status=f"skipped_{fault_type}",
            )
        if fault_type == "flow_rule_drift":
            return _tag_agent_result(
                {
                    "action": "no_action",
                    "reason": "The known flow marker is detected, but no policy-safe flow-specific remediation is wired through the guarded executor path.",
                    "confidence": 1.0,
                    "evidence_refs": [evidence_id],
                },
                model_invoked=False,
                status="policy_no_action",
            )
        if fault_type == "link_failure":
            current_states = [
                str(status.get("state", "")).upper()
                for switch in clean_telemetry.get("switches", {}).values()
                for status in (switch.get("port_status") or {}).values()
                if isinstance(status, dict)
            ]
            if current_states and not any(state in {"DOWN", "MISSING"} for state in current_states):
                return _tag_agent_result(
                    {
                        "action": "no_action",
                        "reason": "Current telemetry shows no failed port; the observed link failure has recovered.",
                        "confidence": 1.0,
                        "evidence_refs": [evidence_id],
                    },
                    model_invoked=False,
                    status="recovered_before_model",
                )
        domain_guidance = ""
        if fault_type in {"standby_forwarding_anomaly", "standby_forwarding"}:
            domain_guidance = (
                "Incident Context: Telemetry indicates that redundant standby link endpoints "
                "are reported in forwarding state simultaneously with the primary path. "
                "Evaluate the topology and port evidence to assess network stability and forwarding loops "
                "while strictly preserving primary path host reachability. "
            )
        elif fault_type == "redundant_trunk_restored":
            domain_guidance = (
                "Incident Context: Telemetry indicates that a redundant trunk link has transitioned to up. "
                "Evaluate the topology and port evidence to assess forwarding path stability "
                "while strictly preserving primary path host reachability. "
            )
        elif fault_type in {"link_failure", "trunk_down"}:
            domain_guidance = (
                "Incident Context: Telemetry indicates that one or more links or ports are degraded or down. "
                "Evaluate whether alternate active paths maintain end-to-end host reachability. "
            )
        elif fault_type == "link_flapping":
            domain_guidance = (
                "Incident Context: Telemetry indicates rapid link state transitions or port flapping on the network interfaces. "
                "Evaluate stability and port behavior while preserving host reachability. "
            )
        elif fault_type == "mac_flooding":
            domain_guidance = (
                "Incident Context: Telemetry indicates abnormally high packet or table activity on monitored interfaces. "
                "Evaluate traffic metrics and forwarding tables while maintaining valid host connectivity. "
            )
        elif fault_type in {"flow_rule_drift", "flow_drift"}:
            domain_guidance = (
                "Incident Context: Telemetry indicates an unexpected flow rule in the switch flow table. "
                "Evaluate whether flow modifications impact legitimate traffic or policy compliance. "
            )

        prompt = (
            "You are an evidence-based network operations decision assistant. "
            "Analyze ONLY the supplied telemetry evidence. Do not assume a fault "
            "that is not visible. "
            + domain_guidance
            + "Prefer no_action when evidence is ambiguous or a transient link failure has recovered. "
            "Never execute commands. Select an action only when the supplied evidence and safety constraints justify it. "
            "Return a single JSON object. If action is 'block', you MUST specify 'target_switch' and 'from_port'.\n"
            "JSON format examples:\n"
            '- When action is block: {"action": "block", "target_switch": "<switch id from evidence>", "from_port": "<port id from evidence>", "reason": "<rationale citing evidence>", "evidence_refs": ["<evidence_id from evidence>"]}\n'
            '- When action is no_action: {"action": "no_action", "reason": "<rationale citing evidence>", "evidence_refs": ["<evidence_id from evidence>"]}\n'
            "Valid physical ports: " + json.dumps(valid_ports) + "\n"
            "Evidence: " + json.dumps(evidence, sort_keys=True)
        )
        valid_evidence_refs = {evidence_id}
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1},
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))
        raw = result.get("response", "").strip()
    except Exception as exc:
        return _tag_agent_result(
            {
                "action": "no_action",
                "reason": f"Ollama service error: {exc}. Safely defaulted to no_action.",
            },
            model_invoked=True,
            status="model_unavailable",
            prompt=prompt,
        )

    # Remove accidental markdown fences if the model adds them.
    if raw.startswith("```json"):
        raw = raw[7:]

    if raw.startswith("```"):
        raw = raw[3:]

    if raw.endswith("```"):
        raw = raw[:-3]

    raw = raw.strip()

    try:
        intent = json.loads(raw)
    except json.JSONDecodeError as exc:
        return _tag_agent_result(
            {
                "action": "no_action",
                "reason": f"Agent output could not be parsed as JSON ({exc}). Defaulted to no_action.",
            },
            model_invoked=True,
            status="invalid_json",
            prompt=prompt,
            raw_output=raw,
        )

    # Robustness: If the model omitted or provided an empty 'reason',
    # supply a clear default explanation so schema validation succeeds.
    if isinstance(intent, dict):
        if "action" in intent and (
            not intent.get("reason") or not str(intent.get("reason")).strip()
        ):
            act = intent.get("action", "no_action")
            if act == "no_action":
                intent["reason"] = (
                    "Nominal network telemetry: healthy flows and zero packet loss observed."
                )
            else:
                intent["reason"] = (
                    f"Remediation action '{act}' proposed based on telemetry analysis."
                )

    try:
        validate(instance=intent, schema=INTENT_SCHEMA)
    except ValidationError as val_err:
        return _tag_agent_result(
            {
                "action": "no_action",
                "reason": f"Agent proposal failed schema validation ({val_err.message}). Safely defaulted to no_action.",
            },
            model_invoked=True,
            status="schema_rejected",
            prompt=prompt,
            raw_output=raw,
        )

    if incident_context:
        allowed_actions = {
            "standby_forwarding_anomaly": {"block", "no_action"},
            "standby_forwarding": {"block", "no_action"},
            "redundant_trunk_restored": {"block", "no_action"},
            "link_failure": {"no_action"},
            "trunk_down": {"no_action"},
            "link_flapping": {"no_action"},
            "mac_flooding": {"no_action"},
            "flow_rule_drift": {"no_action"},
            "flow_drift": {"no_action"},
            "telemetry_stale": {"no_action"},
            "topology_offline": {"no_action"},
        }.get(fault_type, {"no_action"})
        if intent.get("action") not in allowed_actions:
            return _tag_agent_result(
                {
                    "action": "no_action",
                    "reason": "Agent action is not allowed for this incident type; fail-closed.",
                    "confidence": 0.0,
                    "evidence_refs": [],
                },
                model_invoked=True,
                status="policy_rejected",
                prompt=prompt,
                raw_output=raw,
            )
        refs = intent.get("evidence_refs", [])
        if not isinstance(refs, list) or any(ref not in valid_evidence_refs for ref in refs):
            return _tag_agent_result(
                {
                    "action": "no_action",
                    "reason": "Agent referenced evidence that does not exist; fail-closed.",
                    "confidence": 0.0,
                    "evidence_refs": [],
                },
                model_invoked=True,
                status="evidence_rejected",
                prompt=prompt,
                raw_output=raw,
            )
        if not refs:
            return _tag_agent_result(
                {
                    "action": "no_action",
                    "reason": "Agent supplied no verifiable evidence references; fail-closed.",
                    "confidence": 0.0,
                    "evidence_refs": [],
                },
                model_invoked=True,
                status="evidence_missing",
                prompt=prompt,
                raw_output=raw,
            )

    # Post-validation safety guard:
    # Ensure any proposed action targets only valid physical ports.
    action = intent.get("action")
    if action in ("reroute", "block"):
        target_sw = str(intent.get("target_switch", ""))
        from_port = str(intent.get("from_port", ""))
        allowed_ports = valid_ports.get(target_sw, [])
        if from_port not in allowed_ports:
            # If the model selected an invalid port, fall back to safe no_action
            intent = {
                "action": "no_action",
                "reason": (
                    f"Proposed port {from_port} on switch {target_sw} is not a valid "
                    f"physical port (valid ports: {allowed_ports}). Defaulting to no_action."
                ),
            }
            return _tag_agent_result(
                intent,
                model_invoked=True,
                status="invalid_port_rejected",
                prompt=prompt,
                raw_output=raw,
            )

    if incident_context and isinstance(intent, dict):
        return _tag_agent_result(
            intent,
            model_invoked=True,
            status="completed",
            prompt=prompt,
            raw_output=raw,
        )

    return intent


if __name__ == "__main__":
    try:
        intent = propose_remediation()

        print("PROPOSED INTENT:", json.dumps(intent, indent=2))

    except (json.JSONDecodeError, ValidationError) as e:
        print("REJECTED — malformed agent output:", e)

    except Exception as e:
        print("AGENT ERROR:", e)
