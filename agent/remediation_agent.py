import json
import os
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
DEFAULT_TELEMETRY_PATH = os.path.expanduser(
    "~/netops_guardrail/telemetry/data/latest.json"
)

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
    sanitized = {"switches": {}}
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
            "flows": sw_data.get("flows", [])
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
5. If choosing "no_action", do not specify port fields.
6. If choosing "block" or "reroute", "target_switch" must be a valid switch and "from_port" MUST be strictly one of that switch's valid physical ports: {valid_ports}. Never select or invent any other port.

Respond ONLY with a single JSON object matching this schema:
{schema}
"""


def propose_remediation(
    telemetry_path=None
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

    with urllib.request.urlopen(request) as response:
        result = json.loads(
            response.read().decode("utf-8")
        )

    raw = result["response"].strip()

    # Remove accidental markdown fences if the model adds them.
    if raw.startswith("```json"):
        raw = raw[7:]

    if raw.startswith("```"):
        raw = raw[3:]

    if raw.endswith("```"):
        raw = raw[:-3]

    raw = raw.strip()

    intent = json.loads(raw)

    validate(
        instance=intent,
        schema=INTENT_SCHEMA
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
