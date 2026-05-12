from __future__ import annotations

from dataclasses import dataclass

import dns.resolver


@dataclass(frozen=True)
class DomainPosture:
    domain: str
    status: str  # secure | good | attention | unknown | info
    message: str
    details: dict[str, str]


def assess_domain(domain: str) -> DomainPosture:
    d = (domain or "").strip().lower()
    if not d or " " in d or "." not in d:
        return DomainPosture(
            domain=d,
            status="unknown",
            message="Recommended actions: verify domain spelling and DNS configuration",
            details={},
        )

    try:
        mx_ok = _has_mx(d)
    except Exception:
        return DomainPosture(
            domain=d,
            status="unknown",
            message="Recommended actions: retry later; DNS lookup failed",
            details={},
        )

    spf = _get_spf(d)
    dmarc = _get_dmarc(d)

    details: dict[str, str] = {
        "mx": "present" if mx_ok else "missing",
        "spf": "present" if spf else "missing",
        "dmarc": dmarc or "",
    }

    provider_domains = (
        ".gmail.com",
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "icloud.com",
    )
    if d.endswith(provider_domains):
        # Provider-managed domains: posture is mostly informational.
        return DomainPosture(
            domain=d,
            status="info",
            message="Recommended actions: enable MFA/passkeys and secure recovery options",
            details=details,
        )

    if not mx_ok:
        return DomainPosture(
            domain=d,
            status="unknown",
            message="Recommended actions: verify domain can receive email (MX records)",
            details=details,
        )

    if not dmarc:
        return DomainPosture(
            domain=d,
            status="attention",
            message="Recommended actions: add DMARC policy (p=quarantine/reject) to reduce spoofing risk",
            details=details,
        )

    policy = _parse_dmarc_policy(dmarc)
    if policy == "reject":
        return DomainPosture(
            domain=d,
            status="secure",
            message="Recommended actions: maintain DMARC reject and review SPF alignment periodically",
            details=details,
        )
    if policy == "quarantine":
        return DomainPosture(
            domain=d,
            status="good",
            message="Recommended actions: consider tightening DMARC to p=reject after monitoring",
            details=details,
        )
    if policy == "none":
        return DomainPosture(
            domain=d,
            status="good",
            message="Recommended actions: move from monitoring-only (p=none) to quarantine/reject when ready",
            details=details,
        )

    return DomainPosture(
        domain=d,
        status="unknown",
        message="Recommended actions: verify SPF/DMARC records and retry later",
        details=details,
    )


def _has_mx(domain: str) -> bool:
    try:
        ans = dns.resolver.resolve(domain, "MX")
        return len(list(ans)) > 0
    except Exception:
        return False


def _get_spf(domain: str) -> str:
    try:
        ans = dns.resolver.resolve(domain, "TXT")
    except Exception:
        return ""
    for r in ans:
        s = _txt_record_to_str(r)
        if s.lower().startswith("v=spf1"):
            return s
    return ""


def _get_dmarc(domain: str) -> str:
    name = f"_dmarc.{domain}"
    try:
        ans = dns.resolver.resolve(name, "TXT")
    except Exception:
        return ""
    for r in ans:
        s = _txt_record_to_str(r)
        if "v=dmarc1" in s.lower():
            return s
    return ""


def _parse_dmarc_policy(dmarc: str) -> str:
    # Very small parser: look for "p=" token.
    parts = [p.strip() for p in dmarc.split(";") if p.strip()]
    for p in parts:
        if p.lower().startswith("p="):
            val = p.split("=", 1)[1].strip().lower()
            if val in {"none", "quarantine", "reject"}:
                return val
    return ""


def _txt_record_to_str(record) -> str:
    # dnspython TXT has .strings (bytes segments) in many versions.
    strings = getattr(record, "strings", None)
    if strings:
        try:
            return b"".join(strings).decode("utf-8", errors="replace")
        except Exception:
            pass
    # Fallback.
    s = str(record)
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s
