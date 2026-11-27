"""Non-production approval-evidence verification; trusted key enrolment is external."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class EvidenceDenied(ValueError):
    """Evidence is missing, invalid or inconsistent."""


def canonical(value: object) -> bytes:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return payload.encode("ascii")


def identifier(value: str) -> None:
    pattern = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise EvidenceDenied("invalid identifier")


def uuid_text(value: str) -> None:
    if not isinstance(value, str):
        raise EvidenceDenied("invalid UUID")
    try:
        if str(UUID(value)) != value:
            raise EvidenceDenied("noncanonical UUID")
    except ValueError as exc:
        raise EvidenceDenied("invalid UUID") from exc


@dataclass(frozen=True, slots=True)
class Reservation:
    deployment: str
    tenant: str
    unit: str
    role: str
    generation: str

    def validate(self) -> None:
        for value in (self.deployment, self.tenant, self.unit):
            identifier(value)
        pattern = r"[A-Za-z0-9][A-Za-z0-9_]{0,62}"
        if not isinstance(self.role, str) or re.fullmatch(pattern, self.role) is None:
            raise EvidenceDenied("invalid opaque role name")
        uuid_text(self.generation)


@dataclass(frozen=True, slots=True)
class Approval:
    reservation: Reservation
    approval_id: str
    role_oid: int
    change_ref: str
    approvers: tuple[str, str]
    approved_at: int
    expires_at: int

    def validate(self) -> None:
        self.reservation.validate()
        uuid_text(self.approval_id)
        identifier(self.change_ref)
        if not isinstance(self.role_oid, int) or isinstance(self.role_oid, bool):
            raise EvidenceDenied("invalid OID type")
        if not 0 < self.role_oid < 2**32:
            raise EvidenceDenied("invalid OID")
        if not isinstance(self.approvers, tuple) or len(self.approvers) != 2:
            raise EvidenceDenied("exactly two approvers required")
        for subject in self.approvers:
            identifier(subject)
        if self.approvers[0] == self.approvers[1]:
            raise EvidenceDenied("distinct subjects required")
        for timestamp in (self.approved_at, self.expires_at):
            if not isinstance(timestamp, int) or isinstance(timestamp, bool):
                raise EvidenceDenied("integer epoch seconds required")
        if not 0 <= self.approved_at < self.expires_at:
            raise EvidenceDenied("invalid validity window")

    def signing_bytes(self, subject: str) -> bytes:
        self.validate()
        if subject not in self.approvers:
            raise EvidenceDenied("unexpected approver")
        return b"CEPHAS-LOGISTICSOS-APPROVAL-V1\x00" + canonical(
            {"approval": asdict(self), "signer": subject}
        )


@dataclass(frozen=True, slots=True)
class SignedApproval:
    approval: Approval
    signatures: tuple[bytes, bytes]

    def digest(self) -> str:
        self.approval.validate()
        if not isinstance(self.signatures, tuple) or len(self.signatures) != 2:
            raise EvidenceDenied("exactly two signatures required")
        if any(not isinstance(sig, bytes) or len(sig) != 64 for sig in self.signatures):
            raise EvidenceDenied("invalid Ed25519 signature encoding")
        payload = canonical(
            {"approval": asdict(self.approval), "signatures": [s.hex() for s in self.signatures]}
        )
        return hashlib.sha256(b"CEPHAS-LOGISTICSOS-EVIDENCE-V1\x00" + payload).hexdigest()


def verify_approval(
    evidence: SignedApproval,
    expected: Approval,
    trusted_keys: Mapping[str, bytes],
    *,
    expected_digest: str,
    now: int,
) -> None:
    """Verify both signatures, exact tuple, trusted time and expected database digest."""
    expected.validate()
    if evidence.approval != expected:
        raise EvidenceDenied("approval tuple mismatch")
    if not isinstance(now, int) or isinstance(now, bool):
        raise EvidenceDenied("invalid trusted time")
    if not expected.approved_at <= now < expected.expires_at:
        raise EvidenceDenied("approval not currently valid")
    digest = evidence.digest()
    if not isinstance(expected_digest, str):
        raise EvidenceDenied("invalid expected evidence digest")
    if re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        raise EvidenceDenied("invalid expected evidence digest")
    if not hmac.compare_digest(digest, expected_digest):
        raise EvidenceDenied("approval evidence digest mismatch")
    try:
        first, second = (trusted_keys[s] for s in expected.approvers)
        if not isinstance(first, bytes) or not isinstance(second, bytes):
            raise EvidenceDenied("invalid trusted key encoding")
        if first == second:
            raise EvidenceDenied("distinct trusted public keys required")
        for subject, key, sig in zip(
            expected.approvers, (first, second), evidence.signatures, strict=True
        ):
            Ed25519PublicKey.from_public_bytes(key).verify(sig, expected.signing_bytes(subject))
    except (KeyError, InvalidSignature, ValueError) as exc:
        raise EvidenceDenied("trusted signature verification failed") from exc
