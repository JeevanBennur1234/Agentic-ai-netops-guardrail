"""Persisted human approval gate for safety-critical network remediation.

A human approval is bound to the exact intent, verifier result, and forwarding
relevant topology fingerprint. Approval is single-use, expires, and fails closed
when the topology or proposal changes.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import tempfile
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netops_guardrail.netops_paths import NETOPS_HOME

PROJECT_ROOT = NETOPS_HOME
DEFAULT_APPROVAL_PATH = PROJECT_ROOT / "audit" / "human_approvals.json"
DEFAULT_MAX_TELEMETRY_AGE_SECONDS = 30


class ApprovalError(ValueError):
    """Raised when a proposal cannot be safely approved or executed."""


def _utc_now():
    return datetime.now(timezone.utc)


def _parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def topology_fingerprint(telemetry):
    """Require fresh telemetry, then fingerprint forwarding-relevant state."""
    if not isinstance(telemetry, dict):
        raise ApprovalError("Telemetry is malformed; cannot bind human approval")
    updated_at = _parse_time(telemetry.get("updated_at_utc"))
    if updated_at is None:
        raise ApprovalError("Telemetry freshness timestamp missing; refusing approval")
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)
    age_seconds = (_utc_now() - updated_at).total_seconds()
    if age_seconds < -5:
        raise ApprovalError("Telemetry timestamp is in the future; refusing approval")
    if age_seconds > DEFAULT_MAX_TELEMETRY_AGE_SECONDS:
        raise ApprovalError(
            f"Telemetry is stale ({age_seconds:.1f}s old; maximum is "
            f"{DEFAULT_MAX_TELEMETRY_AGE_SECONDS}s); refusing approval"
        )

    switches = {}
    for switch_id, switch_data in sorted((telemetry.get("switches") or {}).items(), key=lambda item: str(item[0])):
        if not isinstance(switch_data, dict):
            raise ApprovalError("Switch telemetry is malformed; refusing approval")
        ports = switch_data.get("ports") or {}
        states = switch_data.get("stp_port_states") or {}
        port_status = switch_data.get("port_status") or {}
        switches[str(switch_id)] = {
            "ports": sorted(str(port) for port in ports.keys()),
            "stp_port_states": {
                str(port): str(state).upper()
                for port, state in sorted(states.items(), key=lambda item: str(item[0]))
            },
            "port_status": {
                str(port): {
                    "state": str(details.get("state", "UNKNOWN")).upper(),
                    "link_down": bool(details.get("link_down", False)),
                    "admin_down": bool(details.get("admin_down", False)),
                    "reason": str(details.get("reason", "UNKNOWN")).upper(),
                }
                for port, details in sorted(port_status.items(), key=lambda item: str(item[0]))
                if isinstance(details, dict)
            },
        }

    links = []
    for link in telemetry.get("links") or []:
        if not isinstance(link, dict):
            continue
        links.append({
            "src_switch": str(link.get("src_switch", "")),
            "src_port": str(link.get("src_port", "")),
            "dst_switch": str(link.get("dst_switch", "")),
            "dst_port": str(link.get("dst_port", "")),
        })
    links.sort(key=lambda item: tuple(item.values()))

    if not switches:
        raise ApprovalError("No switch topology is available; cannot approve remediation")
    return _sha256({"switches": switches, "links": links})


def topology_fingerprint_from_path(telemetry_path):
    try:
        with open(telemetry_path, "r", encoding="utf-8") as handle:
            telemetry = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ApprovalError(f"Current telemetry unavailable; refusing approval: {exc}") from exc
    return topology_fingerprint(telemetry)


class HumanApprovalStore:
    """Small atomic JSON store for reviewable, expiring, single-use approvals."""

    def __init__(self, path=None, ttl_seconds=300):
        self.path = Path(path or DEFAULT_APPROVAL_PATH)
        self.ttl_seconds = max(30, int(ttl_seconds))
        self._lock = threading.RLock()
        self._lock_path = Path(str(self.path) + ".lock")

    @contextmanager
    def _exclusive_lock(self):
        """Coordinate approval lifecycle changes across threads and worker processes."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self._lock_path.open("a+", encoding="utf-8") as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def proposal_fingerprint(intent, verifier_result, topology_fp):
        return _sha256({
            "intent": intent,
            "verifier_result": verifier_result,
            "topology_fingerprint": topology_fp,
        })

    def _read(self):
        if not self.path.exists():
            return []
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ApprovalError(f"Approval store unreadable; refusing operation: {exc}") from exc
        if not isinstance(value, list):
            raise ApprovalError("Approval store has invalid format; refusing operation")
        return value

    def _write(self, proposals):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".human-approvals-", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(proposals, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def create_proposal(self, intent, verifier_result, telemetry_path, requested_by="agent"):
        if not isinstance(intent, dict) or intent.get("action") != "block":
            raise ApprovalError("Only a validated block proposal requires this human approval workflow")
        if not isinstance(verifier_result, dict) or verifier_result.get("safe") is not True:
            raise ApprovalError("Unsafe or missing verifier result cannot be sent for approval")
        topology_fp = topology_fingerprint_from_path(telemetry_path)
        now = _utc_now()
        proposal_id = uuid.uuid4().hex
        fingerprint = self.proposal_fingerprint(intent, verifier_result, topology_fp)
        proposal = {
            "proposal_id": proposal_id,
            "status": "pending",
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=self.ttl_seconds)).isoformat(),
            "requested_by": str(requested_by)[:128],
            "intent": copy.deepcopy(intent),
            "verifier_result": copy.deepcopy(verifier_result),
            "topology_fingerprint": topology_fp,
            "proposal_fingerprint": fingerprint,
            "decision": None,
            "consumed_at": None,
        }
        with self._exclusive_lock():
            proposals = self._read()
            for existing in proposals:
                if (existing.get("status") == "pending"
                        and existing.get("proposal_fingerprint") == fingerprint):
                    if not self._is_expired(existing):
                        return copy.deepcopy(existing)
                    existing["status"] = "expired"
            proposals.append(proposal)
            self._write(proposals)
        return copy.deepcopy(proposal)

    def get_proposal(self, proposal_id):
        with self._exclusive_lock():
            for proposal in self._read():
                if proposal.get("proposal_id") == proposal_id:
                    return copy.deepcopy(proposal)
        return None

    def list_proposals(self, include_decided=False):
        with self._exclusive_lock():
            proposals = self._read()
        if not include_decided:
            proposals = [p for p in proposals if p.get("status") == "pending" and not self._is_expired(p)]
        return copy.deepcopy(proposals)

    @staticmethod
    def _is_expired(proposal):
        expiry = _parse_time(proposal.get("expires_at"))
        return expiry is None or _utc_now() >= expiry

    def decide(self, proposal_id, decision, approver_id, reason="", proposal_fingerprint_value=None):
        normalized = str(decision).strip().lower()
        if normalized not in {"approve", "approved", "reject", "rejected", "request_changes", "changes_requested"}:
            raise ApprovalError("Decision must be approve, reject, or request_changes")
        if not str(approver_id).strip():
            raise ApprovalError("Authenticated approver identity is required")
        if not str(reason).strip():
            raise ApprovalError("A non-empty decision reason is required")
        if normalized in {"approve", "approved"}:
            status = "approved"
        elif normalized in {"request_changes", "changes_requested"}:
            status = "changes_requested"
        else:
            status = "rejected"
        with self._exclusive_lock():
            proposals = self._read()
            for proposal in proposals:
                if proposal.get("proposal_id") != proposal_id:
                    continue
                if proposal.get("status") != "pending":
                    raise ApprovalError(f"Proposal is no longer pending (status={proposal.get('status')})")
                if self._is_expired(proposal):
                    proposal["status"] = "expired"
                    self._write(proposals)
                    raise ApprovalError("Proposal expired; generate a fresh proposal")
                if not proposal_fingerprint_value or not hmac_compare(
                    str(proposal_fingerprint_value), str(proposal.get("proposal_fingerprint", ""))
                ):
                    raise ApprovalError("Proposal fingerprint missing or changed; refusing human decision")
                proposal["status"] = status
                proposal["decision"] = {
                    "decision": status,
                    "approver_id": str(approver_id)[:128],
                    "reason": str(reason)[:1000],
                    "decided_at": _utc_now().isoformat(),
                    "proposal_fingerprint": proposal["proposal_fingerprint"],
                }
                self._write(proposals)
                return copy.deepcopy(proposal)
        raise ApprovalError("Proposal not found")

    def validate_approved(self, proposal_id, intent, verifier_result, telemetry_path):
        with self._exclusive_lock():
            proposal = next(
                (p for p in self._read() if p.get("proposal_id") == proposal_id), None
            )
        if proposal is None:
            raise ApprovalError("Human approval not found")
        if proposal.get("status") != "approved":
            raise ApprovalError(f"Human approval is not usable (status={proposal.get('status')})")
        if self._is_expired(proposal):
            raise ApprovalError("Human approval expired; a fresh review is required")
        current_topology_fp = topology_fingerprint_from_path(telemetry_path)
        current_fp = self.proposal_fingerprint(intent, verifier_result, current_topology_fp)
        if current_fp != proposal.get("proposal_fingerprint"):
            raise ApprovalError("Proposal, verifier result, or topology changed after approval")
        if not proposal.get("decision", {}).get("approver_id"):
            raise ApprovalError("Approval identity missing; refusing execution")
        return copy.deepcopy(proposal)

    def consume_approval(self, proposal_id, intent, verifier_result, telemetry_path):
        """Atomically validate and mark an approved proposal as consumed exactly once."""
        with self._exclusive_lock():
            proposals = self._read()
            proposal = next((p for p in proposals if p.get("proposal_id") == proposal_id), None)
            if proposal is None:
                raise ApprovalError("Human approval not found")
            if proposal.get("status") != "approved":
                raise ApprovalError(f"Human approval is not usable (status={proposal.get('status')})")
            if self._is_expired(proposal):
                proposal["status"] = "expired"
                self._write(proposals)
                raise ApprovalError("Human approval expired; a fresh review is required")
            current_topology_fp = topology_fingerprint_from_path(telemetry_path)
            current_fp = self.proposal_fingerprint(intent, verifier_result, current_topology_fp)
            if current_fp != proposal.get("proposal_fingerprint"):
                raise ApprovalError("Proposal, verifier result, or topology changed after approval")
            if not proposal.get("decision", {}).get("approver_id"):
                raise ApprovalError("Approval identity missing; refusing execution")
            proposal["status"] = "consumed"
            proposal["consumed_at"] = _utc_now().isoformat()
            self._write(proposals)
            return copy.deepcopy(proposal)


def hmac_compare(left, right):
    """Constant-time comparison for proposal fingerprints."""
    import hmac
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
