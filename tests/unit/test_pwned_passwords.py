from __future__ import annotations

import httpx

from pwnchecker.providers.pwned_passwords import (
    PwnedPasswordsClient,
    _parse_range_response_for_suffix,
)


def test_parse_range_response_for_suffix() -> None:
    body = "ABCDEF:2\r\n123456:9\r\n"
    assert _parse_range_response_for_suffix(body, "ABCDEF") == 2
    assert _parse_range_response_for_suffix(body, "abcdef") == 2
    assert _parse_range_response_for_suffix(body, "000000") == 0


def test_check_password_uses_range_api() -> None:
    # password="password" sha1 is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    # prefix: 5BAA6, suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    expected_suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/5BAA6")
        body = f"{expected_suffix}:42\r\nDEADBEEF:1\r\n"
        return httpx.Response(200, text=body)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    pp = PwnedPasswordsClient(client=client)
    res = pp.check_password("password")
    assert res.count == 42
    assert res.prefix5 == "5BAA6"


def test_check_sha1_uses_range_api() -> None:
    sha1_hex = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    expected_suffix = sha1_hex[5:]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/5BAA6")
        return httpx.Response(200, text=f"{expected_suffix}:7\r\n")

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    pp = PwnedPasswordsClient(client=client)
    res = pp.check_sha1(sha1_hex)
    assert res.count == 7
