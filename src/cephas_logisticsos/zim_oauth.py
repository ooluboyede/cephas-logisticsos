"""Isolated ZIM sandbox OAuth lifecycle prototype; no live transport or runtime wiring."""

import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from time import monotonic

_ENDPOINT = "https://apigw.zim.com/authorize/v1"
_MAX_TTL = 3600
_REFRESH_MARGIN = 30
_BEARER = re.compile(r"[A-Za-z0-9._~+/\-]+=*")


class OAuthError(RuntimeError):
    """Sanitized, fail-closed authentication error."""


class Product(Enum):
    TRACING = "Tracing - Sandbox"
    SCHEDULE = "Vessel Schedule - Sandbox"


@dataclass(frozen=True, slots=True)
class Binding:
    """A scope supplied by a future trusted, authorized composition root."""

    tenant: str
    business_unit: str
    product: Product

    def __post_init__(self) -> None:
        if (
            not isinstance(self.tenant, str)
            or not self.tenant.strip()
            or not isinstance(self.business_unit, str)
            or not self.business_unit.strip()
            or not isinstance(self.product, Product)
        ):
            raise OAuthError("invalid sandbox binding")


@dataclass(frozen=True, slots=True)
class Credentials:
    client_id: str = field(repr=False)
    secret: str = field(repr=False)
    revision: str = field(repr=False)


@dataclass(frozen=True, slots=True, eq=False)
class AccessToken:
    value: str = field(repr=False)
    expires_at: float


class SandboxOAuth:
    """One manager per authorized binding; injected dependencies are trusted.

    The provider must change revision whenever credentials rotate.
    Transport must eventually enforce TLS, no redirects, size/time limits and redaction.
    This prototype intentionally ships without a network transport or tenant resolver.
    """

    def __init__(
        self,
        binding: Binding,
        provider: Callable[[Binding], Credentials],
        transport: Callable[[str, Mapping[str, str]], Mapping[str, object]],
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._binding = binding
        self._provider = provider
        self._transport = transport
        self._clock = clock
        self._lock = Lock()
        self._token: AccessToken | None = None
        self._revision: str | None = None

    def _clear(self) -> None:
        self._token = None
        self._revision = None

    def get_token(self, binding: Binding) -> AccessToken:
        if binding != self._binding:
            raise OAuthError("sandbox binding mismatch")
        with self._lock:
            try:
                credentials = self._provider(self._binding)
                if not all(
                    isinstance(value, str) and value.strip()
                    for value in (credentials.client_id, credentials.secret, credentials.revision)
                ):
                    raise OAuthError("invalid credentials")
                now = self._clock()
                if not math.isfinite(now):
                    raise OAuthError("invalid clock")
                token = self._token
                if (
                    token is not None
                    and self._revision == credentials.revision
                    and now < token.expires_at - _REFRESH_MARGIN
                ):
                    return token
                self._clear()
                payload = self._transport(
                    _ENDPOINT,
                    {
                        "grant_type": "client_credentials",
                        "client_id": credentials.client_id,
                        "client_secret": credentials.secret,
                        "scope": self._binding.product.value,
                    },
                )
                value = payload.get("access_token")
                ttl = payload.get("expires_in")
                token_type = payload.get("token_type")
                if (
                    not isinstance(value, str)
                    or len(value) > 16384
                    or _BEARER.fullmatch(value) is None
                    or not isinstance(ttl, int)
                    or isinstance(ttl, bool)
                    or ttl <= _REFRESH_MARGIN
                    or not isinstance(token_type, str)
                    or token_type.lower() != "bearer"
                ):
                    raise OAuthError("invalid token response")
                expires_at = now + min(ttl, _MAX_TTL)
                finished = self._clock()
                if (
                    not math.isfinite(finished)
                    or finished < now
                    or finished >= expires_at - _REFRESH_MARGIN
                ):
                    raise OAuthError("token lifetime exhausted")
                self._token = AccessToken(value, expires_at)
                self._revision = credentials.revision
                return self._token
            except Exception:
                self._clear()
            # Raise outside the handler so the provider/transport exception is not chained.
            raise OAuthError("sandbox authentication failed")

    def invalidate(self, binding: Binding, token: AccessToken) -> None:
        """Discard only the exact token that failed; never evict a newer token."""
        if binding != self._binding:
            raise OAuthError("sandbox binding mismatch")
        with self._lock:
            if self._token is token:
                self._clear()
