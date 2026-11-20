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

from cephas_logisticsos.core.identifiers import validate_identifier


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


# This capability is deliberately private and is reserved for trusted adapter
# code inside the application composition boundary. Python cannot prevent
# arbitrary code in the same process from introspecting private module state.
_TRUSTED_ADAPTER_CAPABILITY = object()


@dataclass(frozen=True, slots=True, init=False)
class _VerifiedTenantMembership:
    """Internal evidence issued only by the trusted adapter boundary."""

    subject_id: str
    tenant_id: str
    business_unit_id: str

    def __init__(
        self,
        *,
        capability: object,
        subject_id: str,
        tenant_id: str,
        business_unit_id: str,
    ) -> None:
        if capability is not _TRUSTED_ADAPTER_CAPABILITY:
            raise TypeError("verified membership evidence is issued by trusted adapters only")
        _validate_id(subject_id, field_name="subject_id")
        _validate_id(tenant_id, field_name="tenant_id")
        _validate_id(business_unit_id, field_name="business_unit_id")
        object.__setattr__(self, "subject_id", subject_id)
        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "business_unit_id", business_unit_id)


def _issue_verified_membership_from_trusted_adapter(
    principal: AuthenticatedPrincipal,
    membership: TenantMembership,
    *,
    capability: object,
) -> _VerifiedTenantMembership:
    """Issue evidence after trusted authentication and authoritative lookup.

    Import this private function only from the configured authentication /
    membership adapter. Never call it from request handlers or with values
    derived solely from client-controlled input.
    """
    if capability is not _TRUSTED_ADAPTER_CAPABILITY:
        raise TenantContextError("trusted adapter capability is required")
    if type(principal) is not AuthenticatedPrincipal:
        raise TenantContextError("authenticated principal is required")
    if type(membership) is not TenantMembership:
        raise TenantContextError("trusted tenant membership is required")
    if not principal.is_authenticated:
        raise TenantContextError("authenticated principal is required")
    if not membership.is_active:
        raise TenantContextError("tenant membership is inactive")
    if principal.subject_id != membership.subject_id:
        raise TenantContextError("principal does not match tenant membership")

    return _VerifiedTenantMembership(
        capability=_TRUSTED_ADAPTER_CAPABILITY,
        subject_id=principal.subject_id,
        tenant_id=membership.tenant_id,
        business_unit_id=membership.business_unit_id,
    )


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
        evidence: _VerifiedTenantMembership,
    ) -> TenantScope:
        """Build scope from internal evidence issued by trusted adapters."""
        if type(evidence) is not _VerifiedTenantMembership:
            raise TenantContextError("trusted adapter-issued membership evidence is required")

        scope = object.__new__(cls)
        object.__setattr__(scope, "subject_id", evidence.subject_id)
        object.__setattr__(scope, "tenant_id", evidence.tenant_id)
        object.__setattr__(scope, "business_unit_id", evidence.business_unit_id)
        return scope
