"""Immutable tenant and business-unit request scope contracts.

A scope must be created only after authentication and a server-side membership
lookup. Never construct it from tenant identifiers supplied by a client.

Python cannot provide an absolute security boundary around object construction.
Direct construction is disabled and downstream authorization must still verify
the scope.
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
    """Principal identity established by the configured authentication layer.

    This validates shape, not the provenance or cryptographic validity of identity.
    """

    subject_id: str
    is_authenticated: bool

    def __post_init__(self) -> None:
        _validate_id(self.subject_id, field_name="subject_id")
        _validate_boolean(self.is_authenticated, field_name="is_authenticated")


@dataclass(frozen=True, slots=True)
class TenantMembership:
    """Membership record returned by a trusted server-side membership lookup.

    The adapter must verify membership against the authoritative customer store.
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


@dataclass(frozen=True, slots=True, init=False)
class TenantScope:
    """Verified immutable scope; create through the verified-membership factory.

    Python introspection and low-level object allocation can bypass conventions.
    This is not a substitute for authorization or database-enforced isolation.
    """

    subject_id: str
    tenant_id: str
    business_unit_id: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "TenantScope cannot be constructed directly; "
            "use from_verified_membership"
        )

    @classmethod
    def from_verified_membership(
        cls,
        principal: AuthenticatedPrincipal,
        membership: TenantMembership,
    ) -> TenantScope:
        """Build scope from trusted authentication and membership adapters."""
        if not isinstance(principal, AuthenticatedPrincipal):
            raise TenantContextError("authenticated principal is required")
        if not isinstance(membership, TenantMembership):
            raise TenantContextError("trusted tenant membership is required")
        if not principal.is_authenticated:
            raise TenantContextError("authenticated principal is required")
        if not membership.is_active:
            raise TenantContextError("tenant membership is inactive")
        if principal.subject_id != membership.subject_id:
            raise TenantContextError("principal does not match tenant membership")

        scope = object.__new__(cls)
        object.__setattr__(scope, "subject_id", principal.subject_id)
        object.__setattr__(scope, "tenant_id", membership.tenant_id)
        object.__setattr__(scope, "business_unit_id", membership.business_unit_id)
        return scope
