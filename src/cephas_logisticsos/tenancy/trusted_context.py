"""Trusted tenant-context adapter composition boundary."""

from __future__ import annotations

from typing import Protocol

from cephas_logisticsos.tenancy._trusted_adapter import _issue_adapter_evidence
from cephas_logisticsos.tenancy.context import (
    AuthenticatedPrincipal,
    TenantContextError,
    TenantMembership,
    TenantScope,
    _validate_id,
)


class AuthenticationProvider(Protocol):
    """Validates credentials and returns identity established by that result."""

    def authenticate(self, credential: object) -> AuthenticatedPrincipal: ...


class MembershipRepository(Protocol):
    """Loads membership from the authoritative server-side customer store."""

    def get_membership(
        self, *, subject_id: str, tenant_id: str, business_unit_id: str
    ) -> TenantMembership | None: ...


class TrustedTenantContextAdapter:
    """Resolve scope only after trusted authentication and membership lookup.

    Instances must be created by the application composition root with
    deployment-controlled implementations. Never inject request-scoped,
    client-selected, or otherwise caller-controlled providers.
    """

    def __init__(
        self,
        authentication: AuthenticationProvider,
        memberships: MembershipRepository,
    ) -> None:
        self._authentication = authentication
        self._memberships = memberships

    def resolve(self, *, credential: object, tenant_id: str, business_unit_id: str) -> TenantScope:
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
        if membership.tenant_id != tenant_id:
            raise TenantContextError("membership tenant does not match requested tenant")
        if membership.business_unit_id != business_unit_id:
            raise TenantContextError(
                "membership business unit does not match requested business unit"
            )
        evidence = _issue_adapter_evidence(principal, membership)
        return TenantScope.from_verified_membership(evidence)
