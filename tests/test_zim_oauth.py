"""Synthetic-only ZIM OAuth tests; no network or carrier credentials."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from cephas_logisticsos.zim_oauth import (
    Binding,
    Credentials,
    OAuthError,
    Product,
    SandboxOAuth,
)


class Fake:
    def __init__(self):
        self.now = 100.0
        self.revision = "r1"
        self.calls = []
        self.payload = {"access_token": "synthetic.token", "expires_in": 120, "token_type": "Bearer"}
        self.error = False

    def provider(self, binding):
        return Credentials("synthetic-client", "synthetic-secret", self.revision)

    def transport(self, url, form):
        self.calls.append((url, dict(form)))
        if self.error:
            raise ValueError("synthetic-secret")
        return self.payload

    def manager(self, binding):
        return SandboxOAuth(binding, self.provider, self.transport, lambda: self.now)


@pytest.mark.parametrize("product", list(Product))
def test_product_scope_and_cache(product):
    fake = Fake()
    binding = Binding("tenant-a", "unit-a", product)
    manager = fake.manager(binding)
    token = manager.get_token(binding)
    assert manager.get_token(binding) is token
    assert fake.calls == [
        (
            "https://apigw.zim.com/authorize/v1",
            {
                "grant_type": "client_credentials",
                "client_id": "synthetic-client",
                "client_secret": "synthetic-secret",
                "scope": product.value,
            },
        )
    ]
    assert "synthetic.token" not in repr(token)
    assert "synthetic-secret" not in repr(fake.provider(binding))


def test_expiry_rotation_and_stale_invalidation():
    fake = Fake()
    binding = Binding("tenant-a", "unit-a", Product.TRACING)
    manager = fake.manager(binding)
    old = manager.get_token(binding)
    fake.now += 90
    new = manager.get_token(binding)
    assert new is not old
    manager.invalidate(binding, old)
    assert manager.get_token(binding) is new
    fake.revision = "r2"
    rotated = manager.get_token(binding)
    assert rotated is not new
    manager.invalidate(binding, rotated)
    assert manager.get_token(binding) is not rotated
    assert len(fake.calls) == 4


@pytest.mark.parametrize(
    "other",
    [
        Binding("tenant-b", "unit-a", Product.TRACING),
        Binding("tenant-a", "unit-b", Product.TRACING),
        Binding("tenant-a", "unit-a", Product.SCHEDULE),
    ],
)
def test_binding_mismatch(other):
    fake = Fake()
    binding = Binding("tenant-a", "unit-a", Product.TRACING)
    manager = fake.manager(binding)
    with pytest.raises(OAuthError, match="binding mismatch"):
        manager.get_token(other)
    assert not fake.calls


def test_concurrent_cache_single_refresh():
    fake = Fake()
    binding = Binding("tenant-a", "unit-a", Product.TRACING)
    manager = fake.manager(binding)
    with ThreadPoolExecutor(max_workers=8) as pool:
        tokens = list(pool.map(manager.get_token, [binding] * 20))
    assert all(token is tokens[0] for token in tokens)
    assert len(fake.calls) == 1


@pytest.mark.parametrize(
    "bad",
    [
        {"access_token": "bad\nheader"},
        {"access_token": ""},
        {"expires_in": True},
        {"expires_in": 30},
        {"expires_in": "120"},
        {"token_type": "Basic"},
    ],
)
def test_invalid_response_clears_cache(bad):
    fake = Fake()
    binding = Binding("tenant-a", "unit-a", Product.TRACING)
    manager = fake.manager(binding)
    manager.get_token(binding)
    fake.now += 90
    original = fake.payload.copy()
    fake.payload.update(bad)
    with pytest.raises(OAuthError, match="sandbox authentication failed"):
        manager.get_token(binding)
    fake.payload = original
    manager.get_token(binding)
    assert len(fake.calls) == 3


def test_transport_failure_redacted():
    fake = Fake()
    binding = Binding("tenant-a", "unit-a", Product.TRACING)
    manager = fake.manager(binding)
    fake.error = True
    with pytest.raises(OAuthError) as error:
        manager.get_token(binding)
    assert "synthetic-secret" not in str(error.value)
    assert error.value.__context__ is None
    fake.error = False
    manager.get_token(binding)
    assert len(fake.calls) == 2
