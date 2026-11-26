"""Bounded sandbox OAuth HTTPS transport; not wired into application runtime."""

import http.client
import json
import math
import ssl
from collections.abc import Mapping
from time import monotonic
from urllib.parse import urlencode

_ENDPOINT = "https://apigw.zim.com/authorize/v1"
_HOST = "apigw.zim.com"
_PATH = "/authorize/v1"
_SCOPES = frozenset({"Tracing - Sandbox", "Vessel Schedule - Sandbox"})
_FIELDS = frozenset({"grant_type", "client_id", "client_secret", "scope"})
_LIMIT = 65536
_TIMEOUT = 10.0


class TransportError(RuntimeError):
    """Sanitized transport failure."""


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("nonfinite JSON number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite JSON number")
    return number


def _check_budget(start: float) -> None:
    if monotonic() - start >= _TIMEOUT:
        raise ValueError("request budget exceeded")


def sandbox_token_transport(url: str, form: Mapping[str, str]) -> Mapping[str, object]:
    """POST only to the fixed ZIM token endpoint using verified TLS.

    Late results are rejected at phase boundaries. DNS and blocking reads may still
    exceed the budget before returning; this is not a hard cancellation deadline.
    No proxy, redirects, retries, decompression, or logging. Caller must be trusted.
    """
    if url != _ENDPOINT:
        raise TransportError("sandbox endpoint rejected")
    try:
        fields = dict(form)
        if (
            fields.keys() != _FIELDS
            or any(not isinstance(v, str) or not v.strip() for v in fields.values())
            or any(len(v) > 4096 for v in fields.values())
            or fields["grant_type"] != "client_credentials"
            or fields["scope"] not in _SCOPES
        ):
            raise ValueError("invalid OAuth request")
        body = urlencode(fields).encode("ascii")
        if len(body) > _LIMIT:
            raise ValueError("request too large")
        start = monotonic()
        # Avoid create_default_context enabling TLS key logging via SSLKEYLOGFILE.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        _check_budget(start)
        connection = http.client.HTTPSConnection(
            _HOST, port=443, timeout=_TIMEOUT, context=context
        )
        try:
            connection.request(
                "POST",
                _PATH,
                body=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Cache-Control": "no-store",
                },
            )
            _check_budget(start)
            response = connection.getresponse()
            _check_budget(start)
            if response.status != 200 or response.headers.defects:
                raise ValueError("unexpected HTTP status")
            for name in ("Content-Encoding", "Content-Type"):
                if len(response.headers.get_all(name, [])) > 1:
                    raise ValueError("ambiguous response header")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise ValueError("unexpected encoding")
            if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != (
                "application/json"
            ):
                raise ValueError("unexpected media type")
            lengths = response.headers.get_all("Content-Length", [])
            transfer = response.headers.get_all("Transfer-Encoding", [])
            if len(lengths) > 1 or (lengths and transfer):
                raise ValueError("ambiguous response framing")
            if transfer and (len(transfer) != 1 or transfer[0].lower() != "chunked"):
                raise ValueError("unexpected transfer encoding")
            if lengths and (
                not lengths[0].isascii() or not lengths[0].isdigit() or int(lengths[0]) > _LIMIT
            ):
                raise ValueError("invalid response size")
            raw = response.read(_LIMIT + 1)
            _check_budget(start)
            if len(raw) > _LIMIT or (lengths and len(raw) != int(lengths[0])):
                raise ValueError("invalid response length")
            parsed: object = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique,
                parse_constant=_reject_constant,
                parse_float=_finite_float,
            )
            if not isinstance(parsed, dict):
                raise ValueError("invalid response object")
            _check_budget(start)
            return parsed
        finally:
            connection.close()
    except Exception:
        pass
    # Suppress sensitive upstream exceptions and response bodies.
    raise TransportError("sandbox token request failed")
