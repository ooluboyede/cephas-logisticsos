"""Combined lifecycle and transport tests, using mocked HTTPS only."""

import json
from email.message import Message
from unittest.mock import patch
from urllib.parse import parse_qs

import pytest

from cephas_logisticsos.zim_oauth import Binding, Credentials, OAuthError, Product, SandboxOAuth
from cephas_logisticsos.zim_transport import TransportError, sandbox_token_transport

URL = "https://apigw.zim.com/authorize/v1"


def mock_response(connection, value="synthetic.token", status=200):
    response = connection.return_value.getresponse.return_value
    response.status = status
    response.headers = Message()
    response.headers["Content-Type"] = "application/json"
    response.getheader.side_effect = response.headers.get
    response.read.return_value = json.dumps(
        {"access_token": value, "expires_in": 120, "token_type": "Bearer"}
    ).encode()
    return response


@pytest.mark.parametrize("product", list(Product))
def test_composed_cache_expiry_and_rotation(product):
    binding = Binding("tenant-a", "unit-a", product)
    now = [100.0]
    revision = ["r1"]

    def provider(requested):
        assert requested == binding
        return Credentials("synthetic-client", "synthetic-" + revision[0], revision[0])

    manager = SandboxOAuth(binding, provider, sandbox_token_transport, lambda: now[0])
    with patch("http.client.HTTPSConnection") as connection:
        mock_response(connection)
        first = manager.get_token(binding)
        assert manager.get_token(binding) is first
        now[0] += 90
        mock_response(connection, "synthetic.second")
        second = manager.get_token(binding)
        assert second is not first
        revision[0] = "r2"
        mock_response(connection, "synthetic.third")
        third = manager.get_token(binding)
        assert third is not second
        manager.invalidate(binding, second)
        assert manager.get_token(binding) is third
        assert connection.call_count == 3
        form = parse_qs(connection.return_value.request.call_args.kwargs["body"].decode())
        assert form["scope"] == [product.value]
        assert form["client_secret"] == ["synthetic-r2"]
        with pytest.raises(OAuthError):
            manager.get_token(Binding("tenant-b", "unit-a", product))
        assert connection.call_count == 3
        manager.invalidate(binding, third)
        mock_response(connection, status=401)
        with pytest.raises(OAuthError) as error:
            manager.get_token(binding)
        assert error.value.__context__ is None
        mock_response(connection, "synthetic.fourth")
        assert manager.get_token(binding).value == "synthetic.fourth"
        assert connection.call_count == 5


def test_clock_rollback_cannot_return_cached_token():
    binding = Binding("tenant-a", "unit-a", Product.TRACING)
    now = [100.0]
    manager = SandboxOAuth(
        binding,
        lambda _: Credentials("id", "secret", "r1"),
        sandbox_token_transport,
        lambda: now[0],
    )
    with patch("http.client.HTTPSConnection") as connection:
        mock_response(connection)
        old = manager.get_token(binding)
        now[0] = 99.0
        with pytest.raises(OAuthError):
            manager.get_token(binding)
        now[0] = 101.0
        assert manager.get_token(binding) is not old
        assert connection.call_count == 2


def test_late_response_rejected_and_tls_key_logging_disabled(monkeypatch):
    monkeypatch.setenv("SSLKEYLOGFILE", "/nonexistent/synthetic-keylog")
    form = {
        "grant_type": "client_credentials",
        "client_id": "synthetic-client",
        "client_secret": "synthetic-secret",
        "scope": Product.TRACING.value,
    }
    with (
        patch("http.client.HTTPSConnection") as connection,
        patch("cephas_logisticsos.zim_transport.monotonic", side_effect=[0, 0, 0, 0, 11]),
    ):
        mock_response(connection)
        with pytest.raises(TransportError):
            sandbox_token_transport(URL, form)
        context = connection.call_args.kwargs["context"]
        assert context.keylog_filename is None
        assert context.check_hostname
        connection.return_value.close.assert_called_once()


@pytest.mark.parametrize("name", ["Content-Type", "Content-Encoding"])
def test_duplicate_security_headers_rejected(name):
    form = {
        "grant_type": "client_credentials",
        "client_id": "synthetic-client",
        "client_secret": "synthetic-secret",
        "scope": Product.TRACING.value,
    }
    with patch("http.client.HTTPSConnection") as connection:
        response = mock_response(connection)
        if name == "Content-Encoding":
            response.headers[name] = "identity"
        response.headers[name] = "identity"
        with pytest.raises(TransportError):
            sandbox_token_transport(URL, form)
        response.read.assert_not_called()
