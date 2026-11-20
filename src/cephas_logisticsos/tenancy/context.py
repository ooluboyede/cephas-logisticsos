"""Immutable tenant and business-unit request scope contracts.

Public principal and membership objects are untrusted data carriers. They are
never accepted directly by TenantScope. Only the trusted authentication and
membership adapter boundary may issue the internal evidence consumed by the
scope factory.

This is an application-interface boundary, not protection against malicious
code execution inside the Python process. Database authorization and
tenant-enforced isolation remain mandatory.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cephas_logisticsos.core.identifiers import validate_identifier

if TYPE_CHECKING:
    from cephas_logisticsos.tenancy._trusted_adapter import (
        _AdapterIssuedTenantMembershipEvidence,
    )


class TenantContextError(ValueError):
    """Raised when a trusted tenant scope cannot be established."""


def _validate_boolean(value: bool, *, field_name: str) -> None:
    if type(value) is not bool:
        raise TenantContextError(f"{field_name} must be a boolean")


def _validate_id(value: str, *, field_name: str) -> None:
    try:
        validate_identifier(value, field_name=field_name)
    except ValueError as exc:
        raise TenantContextError(str(exc)) from exc


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Untrusted principal data; construction does not prove authentication.

    A trusted authentication adapter must validate the credential and establish
    this value from its validated result. Application request handlers must not
    construct it from request-controlled identity fields.
    """

    subject_id: str
    is_authenticated: bool

    def __post_init__(self) -> None:
        _validate_id(self.subject_id, field_name="subject_id")
        _validate_boolean(self.is_authenticated, field_name="is_authenticated")


@dataclass(frozen=True, slots=True)
class TenantMembership:
    """Untrusted membership data; construction does not prove membership.

    A trusted server-side adapter must retrieve and validate membership against
    the authoritative customer-controlled store. Request headers, query
    parameters and request-body fields are not authoritative sources.
    """

    subject_id: str
    tenant_id: str
    business_unit_id: str
    is_active: bool

    def __post_init__(self) -> None:
        for field_name in ("subject_id", "tenant_id", "business_unit_id"):
            _validate_id(getattr(self, field_name), field_name=field_name)
        _validate_boolean(self.is_active, field_name="is_active")


@dataclass(frozen=True, slots=True, init=False)
class TenantScope:
    """Immutable scope created only from trusted-adapter-issued evidence.

    This factory does not itself authenticate a user or query a membership
    repository. Its input must be issued by those trusted adapters. Python
    introspection and arbitrary code execution inside this process can bypass
    private conventions; this is not a substitute for authorization or
    database-enforced isolation.
    """

    subject_id: str
    tenant_id: str
    business_unit_id: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("TenantScope cannot be constructed directly; use from_verified_membership")

    @classmethod
    def from_verified_membership(
        cls,
        evidence: _AdapterIssuedTenantMembershipEvidence,
    ) -> TenantScope:
        """Build scope only from evidence issued by the trusted adapter module."""
        from cephas_logisticsos.tenancy._trusted_adapter import (
            _AdapterIssuedTenantMembershipEvidence,
        )

        if type(evidence) is not _AdapterIssuedTenantMembershipEvidence:
            raise TenantContextError("trusted adapter-issued membership evidence is required")

        scope = object.__new__(cls)
        object.__setattr__(scope, "subject_id", evidence.subject_id)
        object.__setattr__(scope, "tenant_id", evidence.tenant_id)
        object.__setattr__(scope, "business_unit_id", evidence.business_unit_id)
        return scope
