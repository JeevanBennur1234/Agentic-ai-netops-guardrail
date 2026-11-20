"""Common interface and helpers for controlled network faults."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping, Optional


class Fault(ABC):
    """Contract implemented by each injectable and observable network fault."""

    name: str
    display_name: str
    description: str
    safe_expectation: str
    dangerous_temptation: str
    ground_truth: str

    @abstractmethod
    def injector(self, context: Optional[Mapping[str, Any]] = None) -> dict:
        """Create the fault, or emit a clearly labelled non-mutating demo signal."""

    @abstractmethod
    def restore(self, context: Optional[Mapping[str, Any]] = None) -> dict:
        """Restore the fault without bypassing the guarded remediation workflow."""

    @abstractmethod
    def detector(self, telemetry: Mapping[str, Any]) -> dict:
        """Evaluate telemetry using deterministic rules only."""

    @abstractmethod
    def ground_truth_check(self, context: Optional[Mapping[str, Any]] = None) -> dict:
        """Measure network connectivity using an independently supplied checker."""


def check_connectivity(context: Optional[Mapping[str, Any]] = None) -> dict:
    """Run an injected connectivity checker, failing closed when unavailable."""
    context = context or {}
    checker = context.get("connectivity_checker")
    if not callable(checker):
        return {
            "available": False,
            "passed": False,
            "error": "No connectivity checker was supplied.",
        }
    try:
        result = checker()
    except Exception as exc:
        return {
            "available": True,
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {"available": True, "passed": result is True, "result": result}


def check_callback(
    context: Optional[Mapping[str, Any]],
    callback_name: str,
    failure_message: str,
) -> dict:
    """Run an independent boolean ground-truth callback, failing closed."""
    context = context or {}
    checker = context.get(callback_name)
    if not callable(checker):
        return {
            "available": False,
            "passed": False,
            "error": f"No {callback_name} callback was supplied.",
        }
    try:
        result = checker()
    except Exception as exc:
        return {
            "available": True,
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    passed = result is True or (
        isinstance(result, Mapping) and result.get("passed") is True
    )
    return {
        "available": True,
        "passed": passed,
        "result": result,
        "error": None if passed else failure_message,
    }
