import os
import copy
import pytest
from ecdsa import SigningKey, NIST256p
import hashlib

from audit_trail import AuditTrail, GENESIS_HASH


@pytest.fixture
def tmp_audit_trail(tmp_path):
    log_file = str(tmp_path / "audit_log.json")
    key_file = str(tmp_path / "audit_key.pem")
    return AuditTrail(log_path=log_file, key_path=key_file)


class TestValidAuditChains:

    def test_single_approved_record(self, tmp_audit_trail):
        intent = {"action": "no_action", "reason": "Network healthy"}
        verifier_res = {"safe": True, "checks": ["PASS"]}
        record = tmp_audit_trail.record_decision(
            decision="APPROVED",
            intent=intent,
            verifier_result=verifier_res
        )

        assert record["index"] == 0
        assert record["decision"] == "APPROVED"
        assert record["previous_hash"] == GENESIS_HASH
        assert len(record["current_hash"]) == 64
        assert len(record["signature"]) > 0
        assert len(record["public_key"]) > 0

        # Verify chain integrity
        valid, msg = tmp_audit_trail.verify_chain(tmp_audit_trail.chain)
        assert valid is True
        assert "Chain integrity verified" in msg

    def test_single_rejected_record(self, tmp_audit_trail):
        intent = {"action": "block", "target_switch": "1", "from_port": "4294967294", "reason": "Invalid"}
        verifier_res = {"safe": False, "reason": "Port does not exist"}
        record = tmp_audit_trail.record_decision(
            decision="REJECTED",
            intent=intent,
            verifier_result=verifier_res
        )

        assert record["index"] == 0
        assert record["decision"] == "REJECTED"
        assert record["previous_hash"] == GENESIS_HASH

        valid, msg = tmp_audit_trail.verify_chain(tmp_audit_trail.chain)
        assert valid is True

    def test_multi_record_hash_chaining(self, tmp_audit_trail):
        # Record 1: APPROVED
        r1 = tmp_audit_trail.record_decision(
            decision="APPROVED",
            intent={"action": "no_action", "reason": "ok"},
            verifier_result={"safe": True}
        )
        assert r1["previous_hash"] == GENESIS_HASH

        # Record 2: REJECTED
        r2 = tmp_audit_trail.record_decision(
            decision="REJECTED",
            intent={"action": "block", "target_switch": "1", "from_port": "99", "reason": "bad port"},
            verifier_result={"safe": False}
        )
        assert r2["previous_hash"] == r1["current_hash"]

        # Record 3: APPROVED
        r3 = tmp_audit_trail.record_decision(
            decision="APPROVED",
            intent={"action": "no_action", "reason": "ok again"},
            verifier_result={"safe": True}
        )
        assert r3["previous_hash"] == r2["current_hash"]

        assert len(tmp_audit_trail.chain) == 3
        valid, msg = tmp_audit_trail.verify_chain(tmp_audit_trail.chain)
        assert valid is True

    def test_chain_persistence_and_reload(self, tmp_path):
        log_file = str(tmp_path / "persist_log.json")
        key_file = str(tmp_path / "persist_key.pem")

        at1 = AuditTrail(log_path=log_file, key_path=key_file)
        at1.record_decision("APPROVED", {"action": "no_action", "reason": "1"}, {"safe": True})
        at1.record_decision("REJECTED", {"action": "block", "reason": "2"}, {"safe": False})

        # Load with new instance pointing to same file
        at2 = AuditTrail(log_path=log_file, key_path=key_file)
        assert len(at2.chain) == 2
        valid, msg = at2.verify_chain(at2.chain)
        assert valid is True


class TestAuditTamperDetection:

    def test_tampered_intent_detected(self, tmp_audit_trail):
        tmp_audit_trail.record_decision("APPROVED", {"action": "no_action", "reason": "clean"}, {"safe": True})
        chain_copy = copy.deepcopy(tmp_audit_trail.chain)

        # Attacker tampers with intent (changes no_action to malicious block)
        chain_copy[0]["intent"]["action"] = "block"

        valid, msg = tmp_audit_trail.verify_chain(chain_copy)
        assert valid is False
        assert "Tampering detected" in msg
        assert "Hash mismatch" in msg

    def test_tampered_decision_detected(self, tmp_audit_trail):
        tmp_audit_trail.record_decision("REJECTED", {"action": "block", "reason": "bad"}, {"safe": False})
        chain_copy = copy.deepcopy(tmp_audit_trail.chain)

        # Attacker tampers with decision (changes REJECTED to APPROVED)
        chain_copy[0]["decision"] = "APPROVED"

        valid, msg = tmp_audit_trail.verify_chain(chain_copy)
        assert valid is False
        assert "Tampering detected" in msg

    def test_tampered_verifier_result_detected(self, tmp_audit_trail):
        tmp_audit_trail.record_decision("REJECTED", {"action": "block", "reason": "bad"}, {"safe": False})
        chain_copy = copy.deepcopy(tmp_audit_trail.chain)

        # Attacker tampers with verifier result
        chain_copy[0]["verifier_result"]["safe"] = True

        valid, msg = tmp_audit_trail.verify_chain(chain_copy)
        assert valid is False
        assert "Tampering detected" in msg

    def test_tampered_timestamp_detected(self, tmp_audit_trail):
        tmp_audit_trail.record_decision("APPROVED", {"action": "no_action", "reason": "clean"}, {"safe": True})
        chain_copy = copy.deepcopy(tmp_audit_trail.chain)

        # Attacker tampers with timestamp
        chain_copy[0]["timestamp"] = "2020-01-01T00:00:00Z"

        valid, msg = tmp_audit_trail.verify_chain(chain_copy)
        assert valid is False
        assert "Tampering detected" in msg

    def test_hash_recalculated_without_signature_detected(self, tmp_audit_trail):
        tmp_audit_trail.record_decision("APPROVED", {"action": "no_action", "reason": "clean"}, {"safe": True})
        chain_copy = copy.deepcopy(tmp_audit_trail.chain)

        # Attacker modifies intent AND updates current_hash to match altered content
        chain_copy[0]["intent"]["action"] = "block"
        new_hash = AuditTrail.compute_record_hash(
            previous_hash=chain_copy[0]["previous_hash"],
            timestamp=chain_copy[0]["timestamp"],
            decision=chain_copy[0]["decision"],
            intent=chain_copy[0]["intent"],
            verifier_result=chain_copy[0]["verifier_result"]
        )
        chain_copy[0]["current_hash"] = new_hash

        # But attacker does NOT have the private key to forge the ECDSA signature!
        valid, msg = tmp_audit_trail.verify_chain(chain_copy)
        assert valid is False
        assert "Tampering detected" in msg
        assert "signature" in msg.lower()

    def test_tampered_signature_detected(self, tmp_audit_trail):
        tmp_audit_trail.record_decision("APPROVED", {"action": "no_action", "reason": "clean"}, {"safe": True})
        chain_copy = copy.deepcopy(tmp_audit_trail.chain)

        # Corrupt signature bytes
        sig = bytearray(bytes.fromhex(chain_copy[0]["signature"]))
        sig[5] ^= 0xFF
        chain_copy[0]["signature"] = sig.hex()

        valid, msg = tmp_audit_trail.verify_chain(chain_copy)
        assert valid is False
        assert "Tampering detected" in msg
        assert "signature" in msg.lower()

    def test_broken_hash_chain_link_detected(self, tmp_audit_trail):
        tmp_audit_trail.record_decision("APPROVED", {"action": "no_action", "reason": "1"}, {"safe": True})
        tmp_audit_trail.record_decision("APPROVED", {"action": "no_action", "reason": "2"}, {"safe": True})
        chain_copy = copy.deepcopy(tmp_audit_trail.chain)

        # Corrupt previous_hash of block 1
        chain_copy[1]["previous_hash"] = "f" * 64

        valid, msg = tmp_audit_trail.verify_chain(chain_copy)
        assert valid is False
        assert "Tampering detected" in msg
        assert "Broken chain" in msg

    def test_deleted_intermediate_record_detected(self, tmp_audit_trail):
        tmp_audit_trail.record_decision("APPROVED", {"action": "no_action", "reason": "1"}, {"safe": True})
        tmp_audit_trail.record_decision("REJECTED", {"action": "block", "reason": "2"}, {"safe": False})
        tmp_audit_trail.record_decision("APPROVED", {"action": "no_action", "reason": "3"}, {"safe": True})
        chain_copy = copy.deepcopy(tmp_audit_trail.chain)

        # Attacker deletes record 1 (the REJECTED record)
        del chain_copy[1]

        # Now record 2 (previously 3) points to record 1's hash, which no longer matches record 0
        valid, msg = tmp_audit_trail.verify_chain(chain_copy)
        assert valid is False
        assert "Tampering detected" in msg
