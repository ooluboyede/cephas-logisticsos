"""Reference anchor tests; authority and client are isolated by convention only."""

from __future__ import annotations

import shutil
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from engineering.approval_evidence import EvidenceDenied, Reservation
from engineering.checkpoint_anchor import (
    AnchorClient,
    AnchoredIssuance,
    LocalTestAuthority,
    Receipt,
)
from engineering.issuance_ledger import GENESIS, Checkpoint, IssuanceLedger
from engineering.test_approval_ledger import APPROVAL, RESERVATION, signed


def setup(tmp_path: Path) -> tuple[IssuanceLedger, LocalTestAuthority, AnchorClient]:
    local = IssuanceLedger(tmp_path / "local.sqlite")
    store = IssuanceLedger(tmp_path / "authority.sqlite")
    local.initialize()
    store.initialize()
    key = Ed25519PrivateKey.generate()
    authority = LocalTestAuthority("test", store, key)
    return local, authority, AnchorClient("test", authority, key.public_key())


def test_anchored_approval_and_restart(tmp_path: Path) -> None:
    local, authority, client = setup(tmp_path)
    service = AnchoredIssuance(local, client)
    head = service.reserve(RESERVATION)
    assert head.count == 1
    assert authority.store.current() == head == local.current()
    restarted = AnchoredIssuance(IssuanceLedger(local.path), client)
    evidence, keys = signed()
    restarted.verify_admission_evidence(
        evidence, APPROVAL, keys, database_digest=evidence.digest(), now=150
    )
    with pytest.raises(EvidenceDenied):
        restarted.verify_admission_evidence(
            evidence, APPROVAL, keys, database_digest=evidence.digest(), now=200
        )


def test_local_candidate_is_not_authoritative(tmp_path: Path) -> None:
    local, _, client = setup(tmp_path)
    local.reserve(RESERVATION, expected=GENESIS)
    with pytest.raises(EvidenceDenied):
        AnchoredIssuance(local, client).require_reserved(RESERVATION)


def test_restored_local_store_denied(tmp_path: Path) -> None:
    local, _, client = setup(tmp_path)
    backup = tmp_path / "backup.sqlite"
    shutil.copyfile(local.path, backup)
    service = AnchoredIssuance(local, client)
    service.reserve(RESERVATION)
    shutil.copyfile(backup, local.path)
    with pytest.raises(EvidenceDenied):
        service.require_reserved(RESERVATION)
    with pytest.raises(EvidenceDenied):
        service.reserve(RESERVATION)


def test_authority_unavailable_denies(tmp_path: Path) -> None:
    local, authority, client = setup(tmp_path)
    service = AnchoredIssuance(local, client)
    service.reserve(RESERVATION)
    authority.store.path.unlink()
    with pytest.raises(sqlite3.OperationalError):
        service.require_reserved(RESERVATION)
    assert not authority.store.path.exists()


def test_stale_predecessor_and_duplicate_rejected(tmp_path: Path) -> None:
    _, _, client = setup(tmp_path)
    head = client.append(GENESIS, RESERVATION)
    other = replace(RESERVATION, role="other", generation="10000000-0000-4000-8000-000000000002")
    with pytest.raises(EvidenceDenied):
        client.append(GENESIS, other)
    with pytest.raises(EvidenceDenied):
        client.append(head, RESERVATION)
    assert client.read() == head


def test_wrong_deployment_denied_before_local_append(tmp_path: Path) -> None:
    local, _, client = setup(tmp_path)
    with pytest.raises(EvidenceDenied):
        AnchoredIssuance(local, client).reserve(replace(RESERVATION, deployment="other"))
    assert local.current() == GENESIS


def test_replay_and_wrong_key_denied(tmp_path: Path) -> None:
    _, authority, client = setup(tmp_path)
    old = authority.read("0" * 64)

    class ReplayAuthority:
        def read(self, challenge: str) -> Receipt:
            return old

        def append(self, expected: Checkpoint, record: Reservation, challenge: str) -> Receipt:
            return old

    replay = AnchorClient("test", ReplayAuthority(), client.public_key)
    with pytest.raises(EvidenceDenied):
        replay.read()
    wrong_key = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(EvidenceDenied):
        AnchorClient("test", authority, wrong_key).read()


def test_tampered_receipt_denied(tmp_path: Path) -> None:
    _, authority, client = setup(tmp_path)

    class TamperedAuthority:
        def read(self, challenge: str) -> Receipt:
            receipt = authority.read(challenge)
            return replace(receipt, checkpoint=Checkpoint(1, "a" * 64))

        def append(self, expected: Checkpoint, record: Reservation, challenge: str) -> Receipt:
            raise EvidenceDenied("not supported")

    with pytest.raises(EvidenceDenied):
        AnchorClient("test", TamperedAuthority(), client.public_key).read()


def test_failed_authority_append_blocks_unconfirmed_reservation(tmp_path: Path) -> None:
    local, authority, client = setup(tmp_path)

    class FailingAuthority:
        def read(self, challenge: str) -> Receipt:
            return authority.read(challenge)

        def append(self, expected: Checkpoint, record: Reservation, challenge: str) -> Receipt:
            raise OSError("authority unavailable")

    failing = AnchorClient("test", FailingAuthority(), client.public_key)
    with pytest.raises(OSError):
        AnchoredIssuance(local, failing).reserve(RESERVATION)
    assert local.current().count == 1
    assert client.read() == GENESIS
    with pytest.raises(EvidenceDenied):
        AnchoredIssuance(local, client).require_reserved(RESERVATION)
