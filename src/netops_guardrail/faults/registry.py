"""Central registry for supported fault scenarios."""

from netops_guardrail.faults.flow_rule_drift import FlowRuleDriftFault
from netops_guardrail.faults.link_flapping import LinkFlappingFault
from netops_guardrail.faults.mac_flooding import MacFloodingFault
from netops_guardrail.faults.redundant_trunk import RedundantTrunkRestoredFault
from netops_guardrail.faults.standby_forwarding import StandbyForwardingFault
from netops_guardrail.faults.trunk_down import TrunkDownFault

# Live faults that have real, active network/system injectors
LIVE_INJECTABLE_FAULTS = {
    "trunk_down",
    "redundant_trunk_restored",
    "flow_drift",
    "flow_rule_drift",
    "link_flapping",
    "mac_flooding",
}

# Detection stays purely passive for standby forwarding; no live injector
PASSIVE_ONLY_FAULTS = {
    "standby_forwarding",
    "standby_forwarding_anomaly",
}

FAULTS = {
    fault.name: fault
    for fault in (
        RedundantTrunkRestoredFault(),
        StandbyForwardingFault(),
        FlowRuleDriftFault(),
        LinkFlappingFault(),
        MacFloodingFault(),
        TrunkDownFault(),
    )
}

# Alias resolution mapping
ALIASES = {
    "flow_drift": "flow_rule_drift",
    "standby_forwarding": "standby_forwarding_anomaly",
}


def get_fault(name: str):
    """Return a registered fault by stable identifier or supported alias."""
    resolved_name = ALIASES.get(name, name)
    try:
        return FAULTS[resolved_name]
    except KeyError as exc:
        raise KeyError(f"Unknown fault: {name}") from exc


def list_faults(live_only: bool = False) -> list[dict]:
    """Return serializable fault metadata without executing any fault actions."""
    faults_to_list = FAULTS.values()
    if live_only:
        faults_to_list = [
            f for f in faults_to_list
            if f.name in LIVE_INJECTABLE_FAULTS or ALIASES.get(f.name) in LIVE_INJECTABLE_FAULTS
        ]
    return [
        {
            "name": fault.name,
            "display_name": fault.display_name,
            "description": fault.description,
            "safe_expectation": fault.safe_expectation,
            "dangerous_temptation": fault.dangerous_temptation,
            "ground_truth": fault.ground_truth,
            "has_live_injector": fault.name in LIVE_INJECTABLE_FAULTS,
        }
        for fault in faults_to_list
    ]
