"""Trusted tenant-context composition boundary.

Only this adapter may import the private evidence issuer. Concrete authentication
and membership integrations are supplied by the application composition root.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cephas_logisticsos.tenancy.context import (
    AuthenticatedPrincipal,
    TenantContextError,
    TenantMembership,
    TenantScope,
    _validate_id,
)

_TRUSTED_ADAPTER_CAPABILITY = object()


class AuthenticationProvider(Protocol):
    """Validates credentials and returns identity established by that result."""

    def authenticate(self, credential: object) -> AuthenticatedPrincipal: ...


class MembershipRepository(Protocol):
    """Loads membership from the authoritative server-side customer store."""

    def get_membership(
        self, *, subject_id: str, tenant_id: str, business_unit_id: str
    ) -> TenantMembership | None: ...


@dataclass(frozen=True, slots=True, init=False)
class _AdapterIssuedTenantMembershipEvidence:
    """Internal marker for evidence issued by the trusted adapter flow."""

    subject_id: str
    tenant_id: str
    business_unit_id: str

    def __init__(
        self, *, capability: object, subject_id: str, tenant_id: str,
        business_unit_id: str,
    ) -> None:
        if capability is not _TRUSTED_ADAPTER_CAPABILITY:
            raise TypeError("adapter-issued evidence can only be created by the trusted adapter")
        _validate_id(subject_id, field_name="subject_id")
        _validate_id(tenant_id, field_name="tenant_id")
        _validate_id(business_unit_id, field_name="business_unit_id")
        object.__setattr__(self, "subject_id", subject_id)
        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "business_unit_id", business_unit_id)


def _issue_adapter_evidence(
    principal: AuthenticatedPrincipal, membership: TenantMembership
) -> _AdapterIssuedTenantMembershipEvidence:
    """Private issuer; imports are architecturally restricted by CI."""
    if type(principal) is not AuthenticatedPrincipal or not principal.is_authenticated:
        raise TenantContextError("validated authentication result is required")
    if type(membership) is not TenantMembership or not membership.is_active:
        raise TenantContextError("active authoritative membership is required")
    if principal.subject_id != membership.subject_id:
        raise TenantContextError("principal does not match authoritative membership")
    return _AdapterIssuedTenantMembershipEvidence(
        capability=_TRUSTED_ADAPTER_CAPABILITY,
        subject_id=principal.subject_id,
        tenant_id=membership.tenant_id,
        business_unit_id=membership.business_unit_id,
    )


class TrustedTenantContextAdapter:
    """Resolve scope only after authentication and authoritative membership lookup."""

    def __init__(
        self,
        authentication: AuthenticationProvider,
        memberships: MembershipRepository,
    ) -> None:
        self._authentication = authentication
        self._memberships = memberships

    def resolve(
        self, *, credential: object, tenant_id: str, business_unit_id: str
    ) -> TenantScope:
        _validate_id(tenant_id, field_name="tenant_id")
        _validate_id(business_unit_id, field_name="business_unit_id")
        principal = self._authentication.authenticate(credential)
        if type(principal) is not AuthenticatedPrincipal or not principal.is_authenticated:
            raise TenantContextError("authentication provider did not return a validated principal")
        membership = self._memberships.get_membership(
            subject_id=principal.subject_id,
            tenant_id=tenant_id,
            business_unit_id=business_unit_id,
        )
        if membership is None:
            raise TenantContextError("authoritative tenant membership was not found")
        evidence = _issue_adapter_evidence(principal, membership)
        return TenantScope.from_verified_membership(evidence)
