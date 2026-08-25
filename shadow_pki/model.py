"""Модель данных. Единица счёта — линия сертификата (требования, п. 2.2)."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
import statistics

DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9_-]+\.)+[a-z]{2,}$", re.I)

# Двухуровневые суффиксы, встречающиеся в выборке. Не полный Public Suffix
# List — для корректного разбора экзотических зон список пополняется.
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "com.br", "com.au", "co.jp", "com.tr",
    "com.ua", "org.ua", "net.ua", "com.ru", "net.ru", "org.ru", "pp.ru",
}


def registrable(name: str) -> str:
    """Регистрируемый домен: example.ru для a.b.example.ru."""
    n = name.lstrip("*.").lower().rstrip(".")
    parts = n.split(".")
    if len(parts) < 2:
        return n
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def norm_names(raw):
    out = set()
    for n in raw:
        n = (n or "").strip().lower().rstrip(".")
        if n and DOMAIN_RE.match(n):
            out.add(n)
    return out


@dataclass
class Cert:
    source_id: object = None
    issuer: str = ""
    issuer_key: str = ""
    serial: str = ""
    not_before: datetime = None
    not_after: datetime = None
    names: tuple = ()
    pubkey_sha256: str = None
    key_alg: str = None
    key_size: int = None
    sig_alg: str = None

    def as_dict(self):
        return {
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "names": list(self.names),
            "pubkey_sha256": self.pubkey_sha256,
            "key_alg": self.key_alg,
            "key_size": self.key_size,
            "sig_alg": self.sig_alg,
        }


@dataclass
class Line:
    """Хронологическая цепочка выпусков на один набор имён."""

    names: tuple
    certs: list = field(default_factory=list)
    ownership: str = "unknown"
    ownership_reason: str = ""
    provider: str = None

    def sort(self):
        self.certs.sort(key=lambda c: c.not_before or datetime.min.replace(tzinfo=timezone.utc))

    @property
    def current(self):
        return self.certs[-1] if self.certs else None

    @property
    def issuances(self):
        return len(self.certs)

    @property
    def issuers_ever(self):
        return sorted({c.issuer for c in self.certs if c.issuer})

    def current_expired(self, now):
        na = self.current.not_after if self.current else None
        return bool(na and na < now)

    def days_to_expiry(self, now):
        na = self.current.not_after if self.current else None
        return (na - now).days if na else None

    @property
    def is_wildcard(self):
        return any(n.startswith("*.") for n in self.names)

    @property
    def renewal_rhythm_days(self):
        starts = [c.not_before for c in self.certs if c.not_before]
        gaps = [(b - a).days for a, b in zip(starts, starts[1:]) if (b - a).days > 0]
        return int(statistics.median(gaps)) if gaps else None

    def as_dict(self, now):
        return {
            "names": list(self.names),
            "issuances": self.issuances,
            "issuers_ever": self.issuers_ever,
            "ownership": self.ownership,
            "ownership_reason": self.ownership_reason,
            "provider": self.provider,
            "is_wildcard": self.is_wildcard,
            "current_expired": self.current_expired(now),
            "days_to_expiry": self.days_to_expiry(now),
            "renewal_rhythm_days": self.renewal_rhythm_days,
            "current": self.current.as_dict() if self.current else None,
        }


@dataclass
class NameInfo:
    name: str
    resolves: bool = False
    addresses: tuple = ()
    cname: str = None
    checked: bool = False   # False, если DNS-этап был отключён

    def as_dict(self):
        return {
            "name": self.name,
            "resolves": self.resolves,
            "addresses": list(self.addresses),
            "cname": self.cname,
            "dns_checked": self.checked,
        }


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    text: str
    recommendation: str
    subject: str = ""

    def as_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "subject": self.subject,
            "finding": self.text,
            "recommendation": self.recommendation,
        }
