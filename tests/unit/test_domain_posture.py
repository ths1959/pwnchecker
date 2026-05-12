from __future__ import annotations

import dns.resolver

from pwnchecker.providers import domain_posture


class _Txt:
    def __init__(self, s: str) -> None:
        self.strings = [s.encode("utf-8")]


class _Mx:
    def __init__(self) -> None:
        pass


def test_assess_domain_missing_dmarc(monkeypatch) -> None:
    def fake_resolve(name: str, rdtype: str):
        if rdtype == "MX":
            return [_Mx()]
        if rdtype == "TXT" and name.startswith("_dmarc."):
            raise dns.resolver.NXDOMAIN()
        if rdtype == "TXT":
            return [_Txt("v=spf1 -all")]
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(domain_posture.dns.resolver, "resolve", fake_resolve)
    res = domain_posture.assess_domain("example.com")
    assert res.status == "attention"


def test_assess_domain_dmarc_reject(monkeypatch) -> None:
    def fake_resolve(name: str, rdtype: str):
        if rdtype == "MX":
            return [_Mx()]
        if rdtype == "TXT" and name.startswith("_dmarc."):
            return [_Txt("v=DMARC1; p=reject;")]
        if rdtype == "TXT":
            return [_Txt("v=spf1 -all")]
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(domain_posture.dns.resolver, "resolve", fake_resolve)
    res = domain_posture.assess_domain("example.com")
    assert res.status == "secure"

