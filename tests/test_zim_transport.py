"""Mock HTTPS only: never connect to the carrier or use real credentials."""

import ssl
from email.message import Message
from unittest.mock import patch
from urllib.parse import parse_qs

import pytest

from cephas_logisticsos.zim_transport import TransportError, sandbox_token_transport

URL = "https://apigw.zim.com/authorize/v1"
FORM = {
    "grant_type": "client_credentials",
    "client_id": "synthetic-client",
    "client_secret": "synthetic+secret&value",
    "scope": "Tracing - Sandbox",
}


def response(connection, body=b'{"access_token":"synthetic.token"}', status=200, headers=()):
    result = connection.return_value.getresponse.return_value
    result.status = status
    result.headers = Message()
    result.headers["Content-Type"] = "application/json"
    for key, value in headers:
        result.headers[key] = value
    result.getheader.side_effect = result.headers.get
    result.read.return_value = body
    return result


def test_fixed_tls_and_form():
    with patch("http.client.HTTPSConnection") as connection:
        result = response(connection)
        assert sandbox_token_transport(URL, FORM) == {"access_token": "synthetic.token"}
        args, kwargs = connection.call_args
        assert args == ("apigw.zim.com",)
        assert kwargs["port"] == 443
        assert kwargs["timeout"] == 10.0
        context = kwargs["context"]
        assert context.check_hostname
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        args, kwargs = connection.return_value.request.call_args
        assert args == ("POST", "/authorize/v1")
        assert parse_qs(kwargs["body"].decode()) == {k: [v] for k, v in FORM.items()}
        result.read.assert_called_once_with(65537)
        connection.return_value.close.assert_called_once()


@pytest.mark.parametrize("url", [URL + "?x=1", URL + "/", "http://apigw.zim.com/authorize/v1"])
def test_endpoint_rejected(url):
    with patch("http.client.HTTPSConnection") as connection:
        with pytest.raises(TransportError, match="endpoint rejected"):
            sandbox_token_transport(url, FORM)
        connection.assert_not_called()


@pytest.mark.parametrize("changes", [{"scope": "tracing"}, {"client_secret": ""}, {"extra": "x"}])
def test_invalid_form(changes):
    with patch("http.client.HTTPSConnection") as connection:
        with pytest.raises(TransportError):
            sandbox_token_transport(URL, FORM | changes)
        connection.assert_not_called()


@pytest.mark.parametrize("status", [301, 302, 307, 308, 400, 401, 429, 500])
def test_non_success_never_read_or_follow(status):
    with patch("http.client.HTTPSConnection") as connection:
        result = response(connection, status=status, headers=[("Location", "https://invalid.test")])
        with pytest.raises(TransportError):
            sandbox_token_transport(URL, FORM)
        result.read.assert_not_called()
        connection.return_value.request.assert_called_once()
        connection.return_value.close.assert_called_once()


@pytest.mark.parametrize(
    "body,headers",
    [
        (b"x" * 65537, []),
        (b"{}", [("Content-Length", "65537")]),
        (b"{}", [("Content-Length", "4")]),
        (b"{}", [("Content-Length", "2"), ("Content-Length", "2")]),
        (b"{}", [("Content-Length", "2"), ("Transfer-Encoding", "chunked")]),
        (b"{}", [("Content-Encoding", "gzip")]),
        (b'{"x":1,"x":2}', []),
        (b'{"x":NaN}', []),
        (b"[]", []),
        (b"not-json", []),
    ],
)
def test_invalid_response(body, headers):
    with patch("http.client.HTTPSConnection") as connection:
        response(connection, body=body, headers=headers)
        with pytest.raises(TransportError):
            sandbox_token_transport(URL, FORM)
        connection.return_value.close.assert_called_once()


def test_sensitive_network_error_is_not_chained():
    with patch("http.client.HTTPSConnection") as connection:
        connection.return_value.request.side_effect = OSError(FORM["client_secret"])
        with pytest.raises(TransportError) as error:
            sandbox_token_transport(URL, FORM)
        assert FORM["client_secret"] not in str(error.value)
        assert error.value.__context__ is None
        connection.return_value.close.assert_called_once()
