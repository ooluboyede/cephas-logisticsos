"""Adversarial synthetic checks for the isolated OAuth candidate."""

from email.errors import MissingHeaderBodySeparatorDefect
from email.message import Message
from unittest.mock import patch

import pytest

from cephas_logisticsos.zim_oauth import Binding, Credentials, OAuthError, Product, SandboxOAuth
from cephas_logisticsos.zim_transport import TransportError, sandbox_token_transport

URL = "https://apigw.zim.com/authorize/v1"
FORM = {
    "grant_type": "client_credentials",
    "client_id": "synthetic-client",
    "client_secret": "synthetic-secret",
    "scope": Product.TRACING.value,
}


@pytest.mark.parametrize("change", ["revision", "secret", "revoked"])
def test_inflight_credential_change_never_publishes_token(change):
    binding = Binding("tenant-a", "unit-a", Product.TRACING)
    original = Credentials("client", "first", "r1")
    current = [original]
    calls = []

    def provider(requested):
        assert requested == binding
        if current[0] is None:
            raise RuntimeError("synthetic revocation details")
        return current[0]

    def transport(url, form):
        calls.append(form["client_secret"])
        if len(calls) == 1:
            if change == "revision":
                current[0] = Credentials("client", "first", "r2")
            elif change == "secret":
                current[0] = Credentials("client", "second", "r1")
            else:
                current[0] = None
        return {"access_token": "synthetic.token", "expires_in": 120, "token_type": "Bearer"}

    manager = SandboxOAuth(binding, provider, transport, lambda: 100.0)
    with pytest.raises(OAuthError, match="sandbox authentication failed") as error:
        manager.get_token(binding)
    assert error.value.__context__ is None
    current[0] = Credentials("client", "replacement", "r3")
    assert manager.get_token(binding).value == "synthetic.token"
    assert calls == ["first", "replacement"]


@pytest.mark.parametrize("body", [b'{"n":1e999}', b'{"n":-1e999}'])
def test_overflowing_json_float_rejected(body):
    with patch("http.client.HTTPSConnection") as connection:
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.headers = Message()
        response.headers["Content-Type"] = "application/json"
        response.getheader.side_effect = response.headers.get
        response.read.return_value = body
        with pytest.raises(TransportError):
            sandbox_token_transport(URL, FORM)
        connection.return_value.close.assert_called_once()


@pytest.mark.parametrize("kind", ["defect", "non_ascii_length"])
def test_malformed_headers_rejected_before_read(kind):
    with patch("http.client.HTTPSConnection") as connection:
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.headers = Message()
        response.headers["Content-Type"] = "application/json"
        if kind == "defect":
            response.headers.defects.append(MissingHeaderBodySeparatorDefect())
        else:
            response.headers["Content-Length"] = "２"
        response.getheader.side_effect = response.headers.get
        with pytest.raises(TransportError):
            sandbox_token_transport(URL, FORM)
        response.read.assert_not_called()
        connection.return_value.close.assert_called_once()
