"""Non-production, single-host lifecycle reference; no real infrastructure adapters."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from fcntl import LOCK_EX, LOCK_UN, flock
from pathlib import Path
from typing import Protocol


class LifecycleDenied(RuntimeError):
    """A lifecycle action is not safe to proceed."""


@dataclass(frozen=True, slots=True)
class Identity:
    deployment: str
    tenant: str
    unit: str
    role: str
    generation: str
    oid: int


class Boundary(Protocol):
    """Trusted adapters must independently enforce epoch fencing at the resource."""

    def block_route(self, identity: Identity, epoch: int) -> None: ...
    def route_blocked(self, identity: Identity, epoch: int) -> bool: ...
    def verify_first_admission(self, identity: Identity, epoch: int) -> bool: ...
    def enable_route_if_current(self, identity: Identity, epoch: int) -> None: ...
    def route_enabled(self, identity: Identity, epoch: int) -> bool: ...
    def revoke_vault(self, identity: Identity, epoch: int) -> None: ...
    def disable_login(self, identity: Identity, epoch: int) -> None: ...
    def retire_binding(self, identity: Identity, epoch: int) -> None: ...
    def terminate_and_verify(self, identity: Identity, epoch: int) -> bool: ...
    def retirement_verified(self, identity: Identity, epoch: int) -> bool: ...


class Journal:
    """Local durable intent journal; not a distributed lock or issuance ledger."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.path = directory / "lifecycle.sqlite"
        self.lock = directory / "lifecycle.lock"

    @contextmanager
    def serialized(self) -> Iterator[sqlite3.Connection]:
        # The operator must provision a trusted, private local directory.
        with self.lock.open("a+b") as handle:
            flock(handle, LOCK_EX)
            try:
                with closing(sqlite3.connect(self.path)) as db:
                    db.execute("PRAGMA synchronous=FULL")
                    db.execute(
                        """
                        CREATE TABLE IF NOT EXISTS lifecycle (
                            deployment TEXT NOT NULL,
                            tenant TEXT NOT NULL,
                            unit TEXT NOT NULL,
                            role TEXT NOT NULL UNIQUE,
                            generation TEXT NOT NULL UNIQUE,
                            oid INTEGER NOT NULL,
                            epoch INTEGER NOT NULL CHECK(epoch>0),
                            state TEXT NOT NULL CHECK(state IN
                                ('admitting','active','retiring','retired','quarantined')),
                            PRIMARY KEY(deployment,tenant,unit)
                        )
                        """
                    )
                    db.commit()
                    yield db
            finally:
                flock(handle, LOCK_UN)

    @staticmethod
    def key(identity: Identity) -> tuple[str, str, str]:
        return identity.deployment, identity.tenant, identity.unit

    @classmethod
    def read(cls, db: sqlite3.Connection, identity: Identity) -> tuple[int, str] | None:
        row = db.execute(
            "SELECT role,generation,oid,epoch,state FROM lifecycle "
            "WHERE deployment=? AND tenant=? AND unit=?",
            cls.key(identity),
        ).fetchone()
        if row is None:
            return None
        if tuple(row[:3]) != (identity.role, identity.generation, identity.oid):
            raise LifecycleDenied("identity mismatch; explicit rotation is not implemented")
        epoch, state = row[3:]
        if not isinstance(epoch, int) or isinstance(epoch, bool) or not isinstance(state, str):
            raise LifecycleDenied("invalid journal record")
        return epoch, state

    @classmethod
    def begin_admission(cls, db: sqlite3.Connection, identity: Identity) -> int:
        if cls.read(db, identity) is not None:
            raise LifecycleDenied("existing lifecycle cannot be admitted or replayed")
        db.execute(
            "INSERT INTO lifecycle VALUES (?,?,?,?,?,?,1,'admitting')",
            (*cls.key(identity), identity.role, identity.generation, identity.oid),
        )
        db.commit()
        return 1

    @classmethod
    def change(
        cls,
        db: sqlite3.Connection,
        identity: Identity,
        expected: tuple[int, str],
        epoch: int,
        state: str,
    ) -> None:
        cursor = db.execute(
            "UPDATE lifecycle SET epoch=?,state=? "
            "WHERE deployment=? AND tenant=? AND unit=? AND role=? AND generation=? "
            "AND oid=? AND epoch=? AND state=?",
            (
                epoch,
                state,
                *cls.key(identity),
                identity.role,
                identity.generation,
                identity.oid,
                *expected,
            ),
        )
        if cursor.rowcount != 1:
            raise LifecycleDenied("lifecycle compare-and-set failed")
        db.commit()


class Controller:
    """Serializes lifecycle intent and side effects for one trusted local host."""

    def __init__(self, journal: Journal, boundary: Boundary) -> None:
        self.journal = journal
        self.boundary = boundary

    def _block(self, identity: Identity, epoch: int) -> None:
        self.boundary.block_route(identity, epoch)
        if not self.boundary.route_blocked(identity, epoch):
            raise LifecycleDenied("route fence unconfirmed")

    def _quarantine(
        self, db: sqlite3.Connection, identity: Identity, epoch: int, state: str
    ) -> None:
        # Persist failure before attempting containment. An unconfirmed fence is an incident.
        try:
            self.journal.change(db, identity, (epoch, state), epoch + 1, "quarantined")
        finally:
            self._block(identity, epoch + 1)

    def admit(self, identity: Identity) -> None:
        with self.journal.serialized() as db:
            epoch = self.journal.begin_admission(db, identity)
            try:
                self._block(identity, epoch)
                if not self.boundary.verify_first_admission(identity, epoch):
                    raise LifecycleDenied("committed approval or admission evidence invalid")
                # Adapter must perform a fenced, fresh compare at actual route enablement.
                self.boundary.enable_route_if_current(identity, epoch)
                if not self.boundary.route_enabled(identity, epoch):
                    raise LifecycleDenied("route enablement unconfirmed")
                self.journal.change(db, identity, (epoch, "admitting"), epoch, "active")
            except Exception:
                self._quarantine(db, identity, epoch, "admitting")
                raise

    def retire(self, identity: Identity) -> None:
        with self.journal.serialized() as db:
            current = self.journal.read(db, identity)
            if current is None or current[1] == "retired":
                raise LifecycleDenied("missing or terminal lifecycle")
            epoch = current[0] + 1
            self.journal.change(db, identity, current, epoch, "retiring")
            try:
                self._block(identity, epoch)
                self.boundary.revoke_vault(identity, epoch)
                self.boundary.disable_login(identity, epoch)
                self.boundary.retire_binding(identity, epoch)
                if not self.boundary.terminate_and_verify(identity, epoch):
                    raise LifecycleDenied("backend termination unconfirmed")
                if not self.boundary.retirement_verified(identity, epoch):
                    raise LifecycleDenied("retirement evidence incomplete")
                self.journal.change(db, identity, (epoch, "retiring"), epoch, "retired")
            except Exception:
                self._quarantine(db, identity, epoch, "retiring")
                raise
