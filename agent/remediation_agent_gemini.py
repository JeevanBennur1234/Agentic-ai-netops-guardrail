import json
import os

import google.generativeai as genai
from jsonschema import validate, ValidationError


genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

model = genai.GenerativeModel("gemini-3.8-flash")


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


PROMPT_TEMPLATE = """You are a network remediation assistant.

Given this telemetry snapshot (JSON), decide if an action is needed.

Respond ONLY with a single JSON object matching this schema:

{schema}

Telemetry:
{telemetry}
"""


def propose_remediation(
    telemetry_path="telemetry/data/latest.json"
):

    with open(telemetry_path) as f:
        telemetry = json.load(f)

    prompt = PROMPT_TEMPLATE.format(
        schema=json.dumps(INTENT_SCHEMA),
        telemetry=json.dumps(telemetry)
    )

    response = model.generate_content(prompt)

    raw = response.text.strip().strip("```json").strip("```")

    intent = json.loads(raw)

    validate(
        instance=intent,
        schema=INTENT_SCHEMA
    )

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
