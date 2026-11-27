"""Non-production independent checkpoint authority and admission evidence reference."""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from engineering.approval_evidence import (
    Approval,
    EvidenceDenied,
    Reservation,
    SignedApproval,
    canonical,
    identifier,
    verify_approval,
)
from engineering.issuance_ledger import Checkpoint, IssuanceLedger, entry_hash


def validate_checkpoint(point: Checkpoint) -> None:
    if not isinstance(point.count, int) or isinstance(point.count, bool):
        raise EvidenceDenied("invalid checkpoint count")
    if not 0 <= point.count < 2**63:
        raise EvidenceDenied("invalid checkpoint count")
    if not isinstance(point.head, str) or re.fullmatch(r"[0-9a-f]{64}", point.head) is None:
        raise EvidenceDenied("invalid checkpoint hash")
    if (point.count == 0) != (point.head == "0" * 64):
        raise EvidenceDenied("invalid genesis checkpoint")


@dataclass(frozen=True, slots=True)
class Receipt:
    namespace: str
    action: str
    challenge: str
    checkpoint: Checkpoint
    signature: bytes

    def payload(self) -> bytes:
        identifier(self.namespace)
        if self.action not in ("read", "append"):
            raise EvidenceDenied("invalid receipt action")
        if not isinstance(self.challenge, str):
            raise EvidenceDenied("invalid challenge")
        if re.fullmatch(r"[0-9a-f]{64}", self.challenge) is None:
            raise EvidenceDenied("invalid challenge")
        validate_checkpoint(self.checkpoint)
        return b"CEPHAS-LOGISTICSOS-ANCHOR-V1\x00" + canonical(
            {
                "namespace": self.namespace,
                "action": self.action,
                "challenge": self.challenge,
                "checkpoint": asdict(self.checkpoint),
            }
        )


class Authority(Protocol):
    def read(self, challenge: str) -> Receipt: ...
    def append(self, expected: Checkpoint, record: Reservation, challenge: str) -> Receipt: ...


class LocalTestAuthority:
    """Separate reference store and signing key; not a production external service."""

    def __init__(self, namespace: str, store: IssuanceLedger, key: Ed25519PrivateKey) -> None:
        identifier(namespace)
        self.namespace = namespace
        self.store = store
        self.key = key

    def _receipt(self, action: str, challenge: str, point: Checkpoint) -> Receipt:
        unsigned = Receipt(self.namespace, action, challenge, point, b"")
        return Receipt(self.namespace, action, challenge, point, self.key.sign(unsigned.payload()))

    def read(self, challenge: str) -> Receipt:
        return self._receipt("read", challenge, self.store.current())

    def append(self, expected: Checkpoint, record: Reservation, challenge: str) -> Receipt:
        validate_checkpoint(expected)
        if record.deployment != self.namespace:
            raise EvidenceDenied("anchor deployment mismatch")
        # Validate challenge before any durable mutation.
        Receipt(self.namespace, "append", challenge, expected, b"").payload()
        return self._receipt("append", challenge, self.store.reserve(record, expected=expected))


class AnchorClient:
    """Only accept a fresh challenge response under the configured authority key."""

    def __init__(self, namespace: str, authority: Authority, public_key: Ed25519PublicKey) -> None:
        identifier(namespace)
        self.namespace = namespace
        self.authority = authority
        self.public_key = public_key

    def _verify(self, receipt: Receipt, *, action: str, challenge: str) -> Checkpoint:
        if (
            receipt.namespace != self.namespace
            or receipt.action != action
            or receipt.challenge != challenge
        ):
            raise EvidenceDenied("receipt context mismatch")
        try:
            self.public_key.verify(receipt.signature, receipt.payload())
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise EvidenceDenied("invalid authority receipt") from exc
        return receipt.checkpoint

    def read(self) -> Checkpoint:
        challenge = secrets.token_hex(32)
        return self._verify(self.authority.read(challenge), action="read", challenge=challenge)

    def append(self, expected: Checkpoint, record: Reservation) -> Checkpoint:
        validate_checkpoint(expected)
        record.validate()
        if record.deployment != self.namespace:
            raise EvidenceDenied("anchor deployment mismatch")
        challenge = secrets.token_hex(32)
        result = self._verify(
            self.authority.append(expected, record, challenge),
            action="append",
            challenge=challenge,
        )
        candidate = Checkpoint(expected.count + 1, entry_hash(expected.head, record))
        if result != candidate:
            raise EvidenceDenied("authority appended unexpected record")
        return result


class AnchoredIssuance:
    """Fail-closed reference workflow; no database role creation or route side effects."""

    def __init__(self, local: IssuanceLedger, anchor: AnchorClient) -> None:
        self.local = local
        self.anchor = anchor

    def reserve(self, record: Reservation) -> Checkpoint:
        record.validate()
        if record.deployment != self.anchor.namespace:
            raise EvidenceDenied("anchor deployment mismatch")
        previous = self.anchor.read()
        candidate = self.local.reserve(record, expected=previous)
        confirmed = self.anchor.append(previous, record)
        if confirmed != candidate:
            raise EvidenceDenied("local and authority checkpoints disagree")
        self.require_reserved(record)
        return confirmed

    def require_reserved(self, record: Reservation) -> None:
        if record.deployment != self.anchor.namespace:
            raise EvidenceDenied("anchor deployment mismatch")
        self.local.require_reserved(record, anchored=self.anchor.read())

    def verify_admission_evidence(
        self,
        evidence: SignedApproval,
        expected: Approval,
        trusted_keys: Mapping[str, bytes],
        *,
        database_digest: str,
        now: int,
    ) -> None:
        # Expected tuple and digest must come from the independently trusted primary.
        # This is evidence validation, not a reusable authorization or enable token.
        self.require_reserved(expected.reservation)
        verify_approval(evidence, expected, trusted_keys, expected_digest=database_digest, now=now)
