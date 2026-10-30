import hashlib
import json
import os
from datetime import datetime, timezone

from ecdsa import BadSignatureError, NIST256p, SigningKey, VerifyingKey

from netops_guardrail.netops_paths import NETOPS_HOME

DEFAULT_AUDIT_LOG_PATH = str(NETOPS_HOME / "audit" / "audit_log.json")
DEFAULT_KEY_PATH = str(NETOPS_HOME / "audit" / "audit_key.pem")
GENESIS_HASH = "0" * 64


class AuditTrail:
    """
    Cryptographic Audit Trail using SHA3-256 hash chaining and ECDSA signatures.
    Guarantees tamper-evident logging of all guardrail decisions and execution results.
    """

    def __init__(
        self,
        log_path=None,
        key_path=None,
        signing_key=None,
        auto_load=True
    ):
        self.log_path = log_path or DEFAULT_AUDIT_LOG_PATH
        self.key_path = key_path or DEFAULT_KEY_PATH
        self.chain = []

        # Initialize or load ECDSA keypair
        if signing_key:
            self.signing_key = signing_key
        else:
            self.signing_key = self._load_or_generate_key()

        self.verifying_key = self.signing_key.verifying_key

        if auto_load and os.path.exists(self.log_path):
            self.load_chain()

    def _load_or_generate_key(self):
        """Load persistent ECDSA signing key or generate a new NIST256p key."""
        if os.path.exists(self.key_path):
            try:
                with open(self.key_path, "r", encoding="utf-8") as f:
                    key = SigningKey.from_pem(f.read(), hashfunc=hashlib.sha3_256)
                # The signing key is private material; restrict local filesystem access.
                try:
                    os.chmod(self.key_path, 0o600)
                except OSError:
                    pass
                return key
            except Exception as exc:
                raise RuntimeError(
                    f"Existing audit signing key is unreadable or invalid at {self.key_path}; "
                    "refusing to generate a replacement because that would break audit continuity."
                ) from exc

        # Generate a persistent key with owner-only permissions from creation.
        key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha3_256)
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.to_pem())
        return key

    @staticmethod
    def canonical_serialize(payload):
        """Deterministic JSON serialization for canonical hashing."""
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

    @classmethod
    def compute_record_hash(
        cls,
        previous_hash,
        timestamp,
        decision,
        intent,
        verifier_result,
        execution_result=None
    ):
        """
        Compute SHA3-256 hash over canonical fields of the record.
        Preserves backward-compatibility by only including execution_result if provided.
        """
        payload = {
            "previous_hash": previous_hash,
            "timestamp": timestamp,
            "decision": decision,
            "intent": intent,
            "verifier_result": verifier_result
        }
        if execution_result is not None:
            payload["execution_result"] = execution_result

        canonical_bytes = cls.canonical_serialize(payload)
        return hashlib.sha3_256(canonical_bytes).hexdigest()

    def record_decision(
        self,
        decision,
        intent,
        verifier_result,
        timestamp=None,
        execution_result=None
    ):
        """
        Record an approval lifecycle decision into the hash chain,
        sign it with ECDSA, and append to the persistent audit log.
        """
        if decision not in ("APPROVED", "REJECTED", "PENDING_HUMAN_APPROVAL", "CHANGES_REQUESTED"):
            raise ValueError(
                f"Invalid decision: {decision}. Must be APPROVED, REJECTED, "
                "PENDING_HUMAN_APPROVAL, or CHANGES_REQUESTED."
            )

        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()

        # Link to previous record's hash (or genesis hash if first record)
        previous_hash = (
            self.chain[-1]["current_hash"]
            if self.chain
            else GENESIS_HASH
        )

        # Compute SHA3-256 hash of this record
        current_hash = self.compute_record_hash(
            previous_hash=previous_hash,
            timestamp=timestamp,
            decision=decision,
            intent=intent,
            verifier_result=verifier_result,
            execution_result=execution_result
        )

        # Generate ECDSA signature over current_hash using SHA3-256
        sig_bytes = self.signing_key.sign(
            current_hash.encode("utf-8"),
            hashfunc=hashlib.sha3_256
        )
        signature_hex = sig_bytes.hex()
        public_key_hex = self.verifying_key.to_string().hex()

        record = {
            "index": len(self.chain),
            "timestamp": timestamp,
            "decision": decision,
            "intent": intent,
            "verifier_result": verifier_result,
            "previous_hash": previous_hash,
            "current_hash": current_hash,
            "signature": signature_hex,
            "public_key": public_key_hex
        }
        if execution_result is not None:
            record["execution_result"] = execution_result

        self.chain.append(record)
        self.save_chain()

        return record

    def save_chain(self):
        """Persist audit chain to JSON log file."""
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        with open(self.log_path, "w") as f:
            json.dump(self.chain, f, indent=2)

    def load_chain(self):
        """Load audit chain from JSON log file."""
        if not os.path.exists(self.log_path):
            self.chain = []
            return
        with open(self.log_path, "r") as f:
            self.chain = json.load(f)

    @classmethod
    def verify_record(cls, record, expected_prev_hash):
        """
        Verify the integrity and digital signature of a single audit record.
        Returns (is_valid: bool, error_message: str | None).
        """
        # 1. Check previous hash continuity
        if record.get("previous_hash") != expected_prev_hash:
            return (
                False,
                f"Broken chain at index {record.get('index')}: "
                f"previous_hash {record.get('previous_hash')} != expected {expected_prev_hash}"
            )

        # 2. Recompute and verify current hash
        recomputed_hash = cls.compute_record_hash(
            previous_hash=record.get("previous_hash"),
            timestamp=record.get("timestamp"),
            decision=record.get("decision"),
            intent=record.get("intent"),
            verifier_result=record.get("verifier_result"),
            execution_result=record.get("execution_result")
        )

        if recomputed_hash != record.get("current_hash"):
            return (
                False,
                f"Hash mismatch at index {record.get('index')}: "
                f"computed {recomputed_hash} != stored {record.get('current_hash')}"
            )

        # 3. Verify ECDSA signature
        try:
            pub_hex = record.get("public_key")
            sig_hex = record.get("signature")
            if not pub_hex or not sig_hex:
                return False, f"Missing public_key or signature at index {record.get('index')}"

            vk = VerifyingKey.from_string(
                bytes.fromhex(pub_hex),
                curve=NIST256p,
                hashfunc=hashlib.sha3_256
            )
            sig_bytes = bytes.fromhex(sig_hex)
            msg_bytes = record["current_hash"].encode("utf-8")

            if not vk.verify(sig_bytes, msg_bytes, hashfunc=hashlib.sha3_256):
                return False, f"Signature verification failed at index {record.get('index')}"
        except BadSignatureError:
            return False, f"Bad signature detected at index {record.get('index')}"
        except Exception as e:
            return False, f"Signature validation error at index {record.get('index')}: {e}"

        return True, None

    @classmethod
    def verify_chain(cls, chain):
        """
        Verify the full cryptographic chain from genesis to head.
        Returns (is_valid: bool, reason: str).
        """
        if not chain:
            return True, "Chain is empty"

        expected_prev = GENESIS_HASH

        for i, record in enumerate(chain):
            valid, err = cls.verify_record(record, expected_prev)
            if not valid:
                return False, f"Tampering detected at record {i}: {err}"
            expected_prev = record["current_hash"]

        return True, f"Chain integrity verified ({len(chain)} records)"
