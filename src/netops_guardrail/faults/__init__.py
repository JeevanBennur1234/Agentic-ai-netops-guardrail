"""Reusable network fault definitions and registry."""

from netops_guardrail.faults.registry import FAULTS, get_fault, list_faults

__all__ = ["FAULTS", "get_fault", "list_faults"]
