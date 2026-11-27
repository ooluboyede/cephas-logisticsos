"""Non-production issuance ledger with explicit external checkpoint dependency."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path

from engineering.approval_evidence import EvidenceDenied, Reservation, canonical


@dataclass(frozen=True, slots=True)
class Checkpoint:
    count: int
    head: str


GENESIS = Checkpoint(0, "0" * 64)


def entry_hash(previous: str, record: Reservation) -> str:
    return hashlib.sha256(
        b"CEPHAS-LOGISTICSOS-ISSUANCE-V1\x00" + bytes.fromhex(previous) + canonical(asdict(record))
    ).hexdigest()


class IssuanceLedger:
    """Trusted local disk reference; never substitutes for an independent anchor."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        # mode=rw is intentional: absent ledger must not create a replacement.
        db = sqlite3.connect(self.path.absolute().as_uri() + "?mode=rw", uri=True)
        try:
            db.execute("PRAGMA synchronous=FULL")
        except Exception:
            db.close()
            raise
        return db

    def initialize(self) -> None:
        """Explicit one-time bootstrap in a private directory, never a recovery action."""
        with self.path.open("xb"):
            pass
        with closing(self._connect()) as db, db:
            db.executescript(
                """
                CREATE TABLE reservations (
                    entry_no INTEGER PRIMARY KEY CHECK(entry_no > 0),
                    deployment TEXT NOT NULL,
                    tenant TEXT NOT NULL,
                    unit TEXT NOT NULL,
                    role TEXT NOT NULL,
                    generation TEXT NOT NULL UNIQUE,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    UNIQUE(deployment, role)
                );
                CREATE TRIGGER no_reservation_update BEFORE UPDATE ON reservations
                BEGIN SELECT RAISE(ABORT, 'immutable reservation'); END;
                CREATE TRIGGER no_reservation_delete BEFORE DELETE ON reservations
                BEGIN SELECT RAISE(ABORT, 'immutable reservation'); END;
                """
            )

    @staticmethod
    def _scan(db: sqlite3.Connection) -> tuple[Checkpoint, list[Reservation]]:
        point = GENESIS
        entries: list[Reservation] = []
        rows = db.execute(
            "SELECT entry_no,deployment,tenant,unit,role,generation,previous_hash,entry_hash "
            "FROM reservations ORDER BY entry_no"
        )
        for seq, deployment, tenant, unit, role, generation, previous, digest in rows:
            record = Reservation(deployment, tenant, unit, role, generation)
            record.validate()
            if seq != point.count + 1 or previous != point.head:
                raise EvidenceDenied("ledger sequence or predecessor mismatch")
            if digest != entry_hash(point.head, record):
                raise EvidenceDenied("ledger digest mismatch")
            point = Checkpoint(seq, digest)
            entries.append(record)
        if len({(r.deployment, r.role) for r in entries}) != len(entries):
            raise EvidenceDenied("reused role name")
        if len({r.generation for r in entries}) != len(entries):
            raise EvidenceDenied("reused generation")
        return point, entries

    @classmethod
    def _check(cls, db: sqlite3.Connection, expected: Checkpoint) -> list[Reservation]:
        actual, records = cls._scan(db)
        if actual != expected:
            raise EvidenceDenied("external checkpoint mismatch; no automatic recovery")
        return records

    def reserve(self, record: Reservation, *, expected: Checkpoint) -> Checkpoint:
        """Append under an exact anchored predecessor; returned head is NOT anchored yet."""
        record.validate()
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            entries = self._check(db, expected)
            if any(
                r.generation == record.generation
                or (r.deployment, r.role) == (record.deployment, record.role)
                for r in entries
            ):
                raise EvidenceDenied("role name or generation already reserved")
            next_head = Checkpoint(expected.count + 1, entry_hash(expected.head, record))
            db.execute(
                "INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?)",
                (
                    next_head.count,
                    record.deployment,
                    record.tenant,
                    record.unit,
                    record.role,
                    record.generation,
                    expected.head,
                    next_head.head,
                ),
            )
        return next_head

    def require_reserved(self, record: Reservation, *, anchored: Checkpoint) -> None:
        """No role creation is safe until an independently read anchor matches exactly."""
        record.validate()
        with closing(self._connect()) as db, db:
            db.execute("BEGIN")
            entries = self._check(db, anchored)
            if record not in entries:
                raise EvidenceDenied("exact reservation not present")
