"""Private adapter evidence issuer. Imports are restricted by the CI architecture test."""
from __future__ import annotations

from dataclasses import dataclass

from cephas_logisticsos.tenancy.context import (
    AuthenticatedPrincipal,
    TenantContextError,
    TenantMembership,
    _validate_id,
)

_TRUSTED_ADAPTER_CAPABILITY = object()


@dataclass(frozen=True, slots=True, init=False)
class _AdapterIssuedTenantMembershipEvidence:
    """Internal marker for evidence issued after trusted adapter resolution."""

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
    """Private issuer; only the designated adapter module may import it."""
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
