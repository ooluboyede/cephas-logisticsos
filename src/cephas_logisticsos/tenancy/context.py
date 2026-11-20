"""Immutable tenant and business-unit request scope contracts.

A scope must be created only after authentication and a server-side membership
lookup. Never construct it from tenant identifiers supplied by a client.
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
    """Principal identity established by the configured authentication layer."""

    subject_id: str
    is_authenticated: bool

    def __post_init__(self) -> None:
        _validate_id(self.subject_id, field_name="subject_id")
        _validate_boolean(self.is_authenticated, field_name="is_authenticated")


@dataclass(frozen=True, slots=True)
class TenantMembership:
    """Membership record returned by a trusted server-side membership lookup.

    The repository or identity adapter producing this record is responsible for
    verifying membership against the authoritative customer-controlled store.
    Request headers and request-body fields are not authoritative sources.
    """

    subject_id: str
    tenant_id: str
    business_unit_id: str
    is_active: bool

    def __post_init__(self) -> None:
        for field_name in ("subject_id", "tenant_id", "business_unit_id"):
            _validate_id(getattr(self, field_name), field_name=field_name)
        _validate_boolean(self.is_active, field_name="is_active")


@dataclass(frozen=True, slots=True)
class TenantScope:
    """Validated immutable scope for one principal, tenant and business unit."""

    subject_id: str
    tenant_id: str
    business_unit_id: str

    def __post_init__(self) -> None:
        for field_name in ("subject_id", "tenant_id", "business_unit_id"):
            _validate_id(getattr(self, field_name), field_name=field_name)

    @classmethod
    def from_verified_membership(
        cls,
        principal: AuthenticatedPrincipal,
        membership: TenantMembership,
    ) -> TenantScope:
        """Build scope from an authenticated principal and trusted membership.

        This is an application-level contract, not a substitute for database
        row-level security or transaction-scoped authorization enforcement.
        """
        if not principal.is_authenticated:
            raise TenantContextError("authenticated principal is required")
        if not membership.is_active:
            raise TenantContextError("tenant membership is inactive")
        if principal.subject_id != membership.subject_id:
            raise TenantContextError("principal does not match tenant membership")
        return cls(
            subject_id=principal.subject_id,
            tenant_id=membership.tenant_id,
            business_unit_id=membership.business_unit_id,
        )
