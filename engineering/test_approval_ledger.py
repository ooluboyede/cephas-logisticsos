"""Reference cryptographic and durable ledger tests; no live external anchor."""

from __future__ import annotations

import shutil
import sqlite3
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from engineering.approval_evidence import (
    Approval,
    EvidenceDenied,
    Reservation,
    SignedApproval,
    verify_approval,
)
from engineering.issuance_ledger import GENESIS, IssuanceLedger

RESERVATION = Reservation("test", "A", "1", "scope_a1", "10000000-0000-4000-8000-000000000001")
APPROVAL = Approval(
    RESERVATION,
    "20000000-0000-4000-8000-000000000001",
    12345,
    "change-1",
    ("human-1", "human-2"),
    100,
    200,
)


def signed() -> tuple[SignedApproval, dict[str, bytes]]:
    first, second = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    first_sig = first.sign(APPROVAL.signing_bytes("human-1"))
    second_sig = second.sign(APPROVAL.signing_bytes("human-2"))
    evidence = SignedApproval(APPROVAL, (first_sig, second_sig))
    return evidence, {
        "human-1": first.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        "human-2": second.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    }


def test_two_valid_signatures_and_exact_digest() -> None:
    evidence, keys = signed()
    verify_approval(evidence, APPROVAL, keys, expected_digest=evidence.digest(), now=150)


@pytest.mark.parametrize("now", [99, 200, 201])
def test_invalid_time_denied(now: int) -> None:
    evidence, keys = signed()
    with pytest.raises(EvidenceDenied):
        verify_approval(evidence, APPROVAL, keys, expected_digest=evidence.digest(), now=now)


def test_mismatched_scope_and_digest_denied() -> None:
    evidence, keys = signed()
    other = replace(APPROVAL, reservation=replace(RESERVATION, unit="2"))
    with pytest.raises(EvidenceDenied):
        verify_approval(evidence, other, keys, expected_digest=evidence.digest(), now=150)
    with pytest.raises(EvidenceDenied):
        verify_approval(evidence, APPROVAL, keys, expected_digest="0" * 64, now=150)


def test_tampered_payload_with_recomputed_digest_denied() -> None:
    evidence, keys = signed()
    changed = replace(APPROVAL, role_oid=12346)
    tampered = replace(evidence, approval=changed)
    with pytest.raises(EvidenceDenied):
        verify_approval(tampered, changed, keys, expected_digest=tampered.digest(), now=150)


def test_unknown_subject_and_duplicate_key_denied() -> None:
    evidence, keys = signed()
    with pytest.raises(EvidenceDenied):
        verify_approval(
            evidence,
            APPROVAL,
            {"human-1": keys["human-1"]},
            expected_digest=evidence.digest(),
            now=150,
        )
    keys["human-2"] = keys["human-1"]
    with pytest.raises(EvidenceDenied):
        verify_approval(evidence, APPROVAL, keys, expected_digest=evidence.digest(), now=150)


def test_swapped_signatures_denied() -> None:
    evidence, keys = signed()
    swapped = replace(evidence, signatures=(evidence.signatures[1], evidence.signatures[0]))
    with pytest.raises(EvidenceDenied):
        verify_approval(swapped, APPROVAL, keys, expected_digest=swapped.digest(), now=150)


def test_same_subject_denied() -> None:
    duplicate = replace(APPROVAL, approvers=("human-1", "human-1"))
    with pytest.raises(EvidenceDenied):
        duplicate.validate()


def test_reservation_requires_independent_checkpoint(tmp_path: Path) -> None:
    ledger = IssuanceLedger(tmp_path / "ledger.sqlite")
    ledger.initialize()
    head = ledger.reserve(RESERVATION, expected=GENESIS)
    assert head.count == 1
    with pytest.raises(EvidenceDenied):
        ledger.require_reserved(RESERVATION, anchored=GENESIS)
    ledger.require_reserved(RESERVATION, anchored=head)
    with pytest.raises(EvidenceDenied):
        ledger.require_reserved(replace(RESERVATION, unit="2"), anchored=head)
    with pytest.raises(EvidenceDenied):
        ledger.reserve(RESERVATION, expected=head)
    with pytest.raises(EvidenceDenied):
        ledger.reserve(replace(RESERVATION, role="other"), expected=head)
    with pytest.raises(EvidenceDenied):
        ledger.reserve(
            replace(RESERVATION, generation="10000000-0000-4000-8000-000000000002"),
            expected=head,
        )


def test_missing_ledger_not_recreated(tmp_path: Path) -> None:
    path = tmp_path / "missing.sqlite"
    with pytest.raises(sqlite3.OperationalError):
        IssuanceLedger(path).reserve(RESERVATION, expected=GENESIS)
    assert not path.exists()


def test_restore_and_mutation_denied(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite"
    backup = tmp_path / "old.sqlite"
    ledger = IssuanceLedger(path)
    ledger.initialize()
    shutil.copyfile(path, backup)
    head = ledger.reserve(RESERVATION, expected=GENESIS)
    with closing(sqlite3.connect(path)) as db, db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("DELETE FROM reservations")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE reservations SET unit='2'")
    shutil.copyfile(backup, path)
    with pytest.raises(EvidenceDenied):
        ledger.require_reserved(RESERVATION, anchored=head)
    with pytest.raises(EvidenceDenied):
        ledger.reserve(RESERVATION, expected=head)
