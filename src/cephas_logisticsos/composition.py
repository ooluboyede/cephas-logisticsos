"""Application composition root for trusted tenant-context dependencies.

Concrete production authentication and membership implementations are supplied
by the deployment at startup. Request handlers must receive the constructed
adapter and must never construct substitute providers or adapters themselves.
"""

from __future__ import annotations

from cephas_logisticsos.tenancy.trusted_context import (
    AuthenticationProvider,
    MembershipRepository,
    TrustedTenantContextAdapter,
)


def build_tenant_context_adapter(
    *,
    authentication: AuthenticationProvider,
    memberships: MembershipRepository,
) -> TrustedTenantContextAdapter:
    """Compose the adapter with deployment-controlled trusted dependencies."""
    return TrustedTenantContextAdapter(authentication, memberships)
