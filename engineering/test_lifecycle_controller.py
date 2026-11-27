"""Reference controller tests with in-memory fake infrastructure, not live fencing."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from engineering.lifecycle_controller import Controller, Identity, Journal, LifecycleDenied

IDENTITY = Identity("test", "A", "1", "scope_a1", "generation-1", 12345)


class BoundaryFake:
    def __init__(self) -> None:
        self.epoch = 0
        self.enabled = False
        self.approved = True
        self.terminated = True
        self.retired = False
        self.events: list[str] = []

    def block_route(self, identity: Identity, epoch: int) -> None:
        assert identity == IDENTITY
        if epoch < self.epoch:
            raise LifecycleDenied("stale fence")
        self.epoch = epoch
        self.enabled = False
        self.events.append("block")

    def route_blocked(self, identity: Identity, epoch: int) -> bool:
        return identity == IDENTITY and epoch == self.epoch and not self.enabled

    def verify_first_admission(self, identity: Identity, epoch: int) -> bool:
        return self.approved and not self.retired and self.route_blocked(identity, epoch)

    def enable_route_if_current(self, identity: Identity, epoch: int) -> None:
        if not self.verify_first_admission(identity, epoch):
            raise LifecycleDenied("stale or expired")
        self.enabled = True
        self.events.append("enable")

    def route_enabled(self, identity: Identity, epoch: int) -> bool:
        return identity == IDENTITY and self.epoch == epoch and self.enabled

    def revoke_vault(self, identity: Identity, epoch: int) -> None:
        assert self.route_blocked(identity, epoch)
        self.events.append("vault")

    def disable_login(self, identity: Identity, epoch: int) -> None:
        assert self.route_blocked(identity, epoch)
        self.events.append("login")

    def retire_binding(self, identity: Identity, epoch: int) -> None:
        assert self.route_blocked(identity, epoch)
        self.retired = True
        self.events.append("binding")

    def terminate_and_verify(self, identity: Identity, epoch: int) -> bool:
        assert self.route_blocked(identity, epoch)
        self.events.append("terminate")
        return self.terminated

    def retirement_verified(self, identity: Identity, epoch: int) -> bool:
        return self.retired and self.terminated and self.route_blocked(identity, epoch)


def state(journal: Journal) -> tuple[int, str] | None:
    with journal.serialized() as db:
        return journal.read(db, IDENTITY)


def test_terminal_retirement_and_stale_enable(tmp_path: Path) -> None:
    journal = Journal(tmp_path)
    boundary = BoundaryFake()
    controller = Controller(journal, boundary)
    controller.admit(IDENTITY)
    assert state(journal) == (1, "active")
    controller.retire(IDENTITY)
    assert state(journal) == (2, "retired")
    assert boundary.events == ["block", "enable", "block", "vault", "login", "binding", "terminate"]
    with pytest.raises(LifecycleDenied):
        boundary.enable_route_if_current(IDENTITY, 1)
    with pytest.raises(LifecycleDenied):
        Controller(Journal(tmp_path), boundary).admit(IDENTITY)
    assert not boundary.enabled


def test_expired_approval_quarantines(tmp_path: Path) -> None:
    journal = Journal(tmp_path)
    boundary = BoundaryFake()
    boundary.approved = False
    with pytest.raises(LifecycleDenied):
        Controller(journal, boundary).admit(IDENTITY)
    assert state(journal) == (2, "quarantined")
    assert "enable" not in boundary.events
    assert not boundary.enabled


def test_unconfirmed_termination_not_retired(tmp_path: Path) -> None:
    journal = Journal(tmp_path)
    boundary = BoundaryFake()
    controller = Controller(journal, boundary)
    controller.admit(IDENTITY)
    boundary.terminated = False
    with pytest.raises(LifecycleDenied):
        controller.retire(IDENTITY)
    assert state(journal) == (3, "quarantined")
    assert not boundary.enabled
    boundary.terminated = True
    Controller(Journal(tmp_path), boundary).retire(IDENTITY)
    assert state(journal) == (4, "retired")


def test_interrupted_admission_can_only_retire(tmp_path: Path) -> None:
    journal = Journal(tmp_path)
    boundary = BoundaryFake()
    with journal.serialized() as db:
        journal.begin_admission(db, IDENTITY)
    boundary.block_route(IDENTITY, 1)
    boundary.enable_route_if_current(IDENTITY, 1)
    restarted = Controller(Journal(tmp_path), boundary)
    with pytest.raises(LifecycleDenied):
        restarted.admit(IDENTITY)
    restarted.retire(IDENTITY)
    assert state(journal) == (2, "retired")
    assert not boundary.enabled


def test_concurrent_retirement_waits_for_admission(tmp_path: Path) -> None:
    entered = Event()
    release = Event()
    retire_started = Event()

    class PausedBoundary(BoundaryFake):
        def enable_route_if_current(self, identity: Identity, epoch: int) -> None:
            entered.set()
            if not release.wait(timeout=5):
                raise LifecycleDenied("test release timeout")
            super().enable_route_if_current(identity, epoch)

    boundary = PausedBoundary()
    first = Controller(Journal(tmp_path), boundary)
    second = Controller(Journal(tmp_path), boundary)

    def retire() -> None:
        retire_started.set()
        second.retire(IDENTITY)

    with ThreadPoolExecutor(max_workers=2) as pool:
        activation = pool.submit(first.admit, IDENTITY)
        try:
            assert entered.wait(timeout=5)
            retirement = pool.submit(retire)
            assert retire_started.wait(timeout=5)
            assert not retirement.done()
            assert boundary.events == ["block"]
        finally:
            release.set()
        activation.result(timeout=5)
        retirement.result(timeout=5)
    assert state(Journal(tmp_path)) == (2, "retired")
    assert not boundary.enabled


def test_fresh_compare_required_at_enable(tmp_path: Path) -> None:
    class ExpiringBoundary(BoundaryFake):
        def enable_route_if_current(self, identity: Identity, epoch: int) -> None:
            self.approved = False
            super().enable_route_if_current(identity, epoch)

    boundary = ExpiringBoundary()
    journal = Journal(tmp_path)
    with pytest.raises(LifecycleDenied):
        Controller(journal, boundary).admit(IDENTITY)
    assert state(journal) == (2, "quarantined")
    assert not boundary.enabled
