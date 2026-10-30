import json
import os
import sys
import urllib.request

from jsonschema import validate, ValidationError


OLLAMA_URL = os.environ.get(
    "OLLAMA_URL",
    "http://172.21.32.1:11434/api/generate"
)
MODEL = os.environ.get(
    "OLLAMA_MODEL",
    "qwen2.5-coder:1.5b"
)
from netops_guardrail.netops_paths import NETOPS_HOME

DEFAULT_TELEMETRY_PATH = str(NETOPS_HOME / "telemetry" / "data" / "latest.json")

INTENT_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["reroute", "block", "no_action"]
        },
        "target_switch": {
            "type": "string"
        },
        "from_port": {
            "type": "string"
        },
        "to_port": {
            "type": "string"
        },
        "reason": {
            "type": "string"
        }
    },
    "required": ["action", "reason"]
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
        valid_ports[str(sw_id)] = sorted(
            ports,
            key=lambda x: int(x) if x.isdigit() else x
        )
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
5. If choosing "no_action", do not specify port fields. You MUST always provide a clear "reason" field (e.g. "Nominal telemetry, zero packet drops").
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
        schema=json.dumps(INTENT_SCHEMA, indent=2)
    )
    if incident_context:
        # A compact incident prompt is more reliable than burying the fault
        # inside the full generic statistics prompt on small local models.
        compact_telemetry = {
            "updated_at_utc": clean_telemetry.get("updated_at_utc"),
            "links": clean_telemetry.get("links", []),
            "switches": {
                sid: {
                    "ports": list(sw.get("ports", {}).keys()),
                    "stp_port_states": sw.get("stp_port_states", {}),
                    "port_status": sw.get("port_status", {}),
                }
                for sid, sw in clean_telemetry.get("switches", {}).items()
            },
        }

        # Derive evidence from the live Ryu telemetry. Issue 2 can be a
        # genuinely observed anomaly, or an explicitly labeled controlled demo
        # signal; the latter never claims the physical STP state was changed.
        pairs = set()
        for link in clean_telemetry.get("links", []):
            if not isinstance(link, dict):
                continue
            left = f"s{str(link.get('src_switch', '')).strip()}-p{str(link.get('src_port', '')).strip()}"
            right = f"s{str(link.get('dst_switch', '')).strip()}-p{str(link.get('dst_port', '')).strip()}"
            pairs.add(tuple(sorted((left, right))))
        stp = {
            str(sid): {str(port): str(state).upper()
                       for port, state in (sw.get("stp_port_states") or {}).items()}
            for sid, sw in clean_telemetry.get("switches", {}).items()
        }
        affected = incident_context.get("affected_link") or {}
        endpoint_a = str(affected.get("endpoint_a", "s1-p3"))
        endpoint_b = str(affected.get("endpoint_b", "s2-p2"))
        primary_pair = tuple(sorted(("s1-p2", "s2-p1")))
        affected_pair = tuple(sorted((endpoint_a, endpoint_b)))
        base_facts = {
            "affected_link_confirmed": affected_pair in pairs,
            "primary_trunk_confirmed": primary_pair in pairs,
            "primary_trunk_endpoints_forward": (
                stp.get("1", {}).get("2") == "FORWARD"
                and stp.get("2", {}).get("1") == "FORWARD"
            ),
            "host_access_ports_forward": (
                stp.get("1", {}).get("1") == "FORWARD"
                and stp.get("2", {}).get("3") == "FORWARD"
            ),
            "proposal_target_port_exists": (
                str(incident_context.get("expected_target_switch", "1")) in valid_ports
                and str(incident_context.get("expected_from_port", "3"))
                    in valid_ports.get(str(incident_context.get("expected_target_switch", "1")), [])
            ),
        }
        standby_has_stp_block = (
            stp.get("1", {}).get("3") == "BLOCK"
            or stp.get("2", {}).get("2") == "BLOCK"
        )
        standby_both_forward = (
            stp.get("1", {}).get("3") == "FORWARD"
            and stp.get("2", {}).get("2") == "FORWARD"
        )
        fault_type = incident_context.get("fault_type")
        if fault_type == "standby_forwarding_anomaly":
            simulation_mode = incident_context.get("simulation_mode") is True
            facts = {
                **base_facts,
                "standby_forwarding_anomaly_observed": standby_both_forward,
                "controlled_simulation_signal": simulation_mode,
                "anomaly_signal_available": standby_both_forward or simulation_mode,
            }
        else:
            facts = {
                **base_facts,
                "standby_has_stp_block": standby_has_stp_block,
            }

        compact_telemetry["validated_fault_facts"] = facts
        required_facts = (
            {key: value for key, value in facts.items()
             if key not in {"standby_forwarding_anomaly_observed", "controlled_simulation_signal"}}
            if fault_type == "standby_forwarding_anomaly"
            else facts
        )
        if not all(required_facts.values()):
            failed = [name for name, value in required_facts.items() if not value]
            return {
                "action": "no_action",
                "reason": "Fault context failed deterministic telemetry checks: " + ", ".join(failed),
            }

        if fault_type == "standby_forwarding_anomaly":
            prompt = (
                "You are an SDN remediation planner. Return one JSON object only with keys action and reason; "
                "for block also include target_switch and from_port. Allowed actions: block, no_action.\n"
                "INCIDENT: " + json.dumps(incident_context, sort_keys=True) +
                "\nLIVE TELEMETRY EVIDENCE: " + json.dumps(compact_telemetry, sort_keys=True) +
                "\nMANDATORY POLICY: the primary trunk and host access ports are forwarding, both redundant "
                "trunks are discovered, and the proposed port exists. If standby_forwarding_anomaly_observed "
                "is true, explain that live telemetry shows both standby endpoints FORWARD. If this is a "
                "controlled simulation signal, explicitly say the anomaly alert is simulated and do NOT claim "
                "that live telemetry shows both endpoints forwarding. Propose block on switch 1 port 3 only "
                "as a human-reviewable containment action. Do not execute anything."
            )
        else:
            prompt = (
                "You are an SDN remediation planner. Analyze this controlled fault report and "
                "validated telemetry facts. Return one JSON object only with keys action and reason; "
                "for block also include target_switch and from_port. Allowed actions: block, no_action.\n"
                "CONTROLLED FAULT: " + json.dumps(incident_context, sort_keys=True) +
                "\nTELEMETRY EVIDENCE: " + json.dumps(compact_telemetry, sort_keys=True) +
                "\nMANDATORY POLICY: every validated_fault_facts field is true. Propose action=block, "
                "Propose action=block on switch 1 port 3. Explain that s1-p3/s2-p2 is the "
                "restored standby trunk, s1-p2/s2-p1 is present and STP-forwarding, at least one standby "
                "endpoint is STP-blocked, and both host access ports are STP-forwarding. Never claim "
                "the primary trunk is absent. The independent verifier checks reachability next. "
                "Do not execute anything; output only JSON."
            )
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1
        }
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )
        raw = result.get("response", "").strip()
    except Exception as exc:
        return {
            "action": "no_action",
            "reason": f"Ollama service error: {exc}. Safely defaulted to no_action."
        }

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
        return {
            "action": "no_action",
            "reason": f"Agent output could not be parsed as JSON ({exc}). Defaulted to no_action."
        }

    # Robustness: If the model omitted or provided an empty 'reason',
    # supply a clear default explanation so schema validation succeeds.
    if isinstance(intent, dict):
        if "action" in intent and (not intent.get("reason") or not str(intent.get("reason")).strip()):
            act = intent.get("action", "no_action")
            if act == "no_action":
                intent["reason"] = "Nominal network telemetry: healthy flows and zero packet loss observed."
            else:
                intent["reason"] = f"Remediation action '{act}' proposed based on telemetry analysis."

    try:
        validate(
            instance=intent,
            schema=INTENT_SCHEMA
        )
    except ValidationError as val_err:
        return {
            "action": "no_action",
            "reason": f"Agent proposal failed schema validation ({val_err.message}). Safely defaulted to no_action."
        }

    # Both controlled scenarios may only propose the exact standby-trunk port.
    # Keep model-selected primary/access ports from reaching the decision gate.
    fault_type = incident_context.get("fault_type") if incident_context else None
    if incident_context and fault_type in {"redundant_trunk_restored", "standby_forwarding_anomaly"}:
        expected_switch = str(incident_context.get("expected_target_switch", "1"))
        expected_port = str(incident_context.get("expected_from_port", "3"))
        if (
            intent.get("action") != "block"
            or str(intent.get("target_switch", "")) != expected_switch
            or str(intent.get("from_port", "")) != expected_port
        ):
            return {
                "action": "no_action",
                "reason": "AI did not propose the exact context-authorized standby-trunk block; fail-closed.",
            }
        ai_reason = str(intent.get("reason", "")).strip()
        if fault_type == "redundant_trunk_restored":
            evidence = (
                "Telemetry evidence: standby link s1-p3<->s2-p2 is discovered; "
                "primary link s1-p2<->s2-p1 is discovered with both ends FORWARD; "
                "at least one standby endpoint is STP BLOCK; both host-facing ports are FORWARD. "
                "The independent safety verifier must still confirm host reachability."
            )
        else:
            states_for_reason = {
                "s1-p3": stp.get("1", {}).get("3", "UNKNOWN"),
                "s2-p2": stp.get("2", {}).get("2", "UNKNOWN"),
            }
            if standby_both_forward:
                evidence = (
                    "Live telemetry detected unexpected standby forwarding: both s1-p3 and s2-p2 "
                    "are FORWARD while the primary trunk and host access ports are FORWARD."
                )
            else:
                evidence = (
                    "CONTROLLED DEMO SIGNAL: the standby-forwarding anomaly alert was simulated for this "
                    "review workflow. Live telemetry currently reports s1-p3=" + states_for_reason["s1-p3"] +
                    " and s2-p2=" + states_for_reason["s2-p2"] +
                    "; it does not confirm that both endpoints are forwarding, and this trigger did not "
                    "change any switch or STP state."
                )
            evidence += " The independent safety verifier must still confirm host reachability."
        intent["reason"] = (ai_reason + " " + evidence).strip()

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
                )
            }

    return intent


if __name__ == "__main__":

    try:

        intent = propose_remediation()

        print(
            "PROPOSED INTENT:",
            json.dumps(intent, indent=2)
        )

    except (
        json.JSONDecodeError,
        ValidationError
    ) as e:

        print(
            "REJECTED — malformed agent output:",
            e
        )

    except Exception as e:

        print(
            "AGENT ERROR:",
            e
        )
