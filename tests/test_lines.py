"""Семантика линии сертификата (требования, п. 2.2) на синтетических данных."""

from datetime import datetime, timezone, timedelta

from shadow_pki import collect
from shadow_pki.model import Cert, norm_names

NOW = datetime(2026, 8, 25, tzinfo=timezone.utc)


def cert(names, issuer, serial, nb, days):
    return Cert(issuer=issuer, issuer_key=issuer, serial=serial,
                not_before=nb, not_after=nb + timedelta(days=days),
                names=tuple(sorted(norm_names(names))))


def build():
    certs = []
    for i in range(12):                                   # автопродление + предсертификаты
        nb = NOW - timedelta(days=60 * (12 - i))
        certs += [cert(["a.example.com"], "CA-Free", f"a{i}", nb, 90)] * 2
    certs.append(cert(["old.example.com"], "CA-Comm", "b1", NOW - timedelta(days=500), 365))
    certs.append(cert(["c.example.com"], "CA-Other", "c1", NOW - timedelta(days=78), 90))
    certs.append(cert(["*.example.com", "example.com"], "CA-Comm", "d1", NOW - timedelta(days=10), 365))
    certs.append(cert(["not a domain", "", "e.example.com"], "CA-Comm", "e1", NOW - timedelta(days=10), 90))
    return certs


def run(check):
    deduped, collapsed = collect.dedup_precerts(build())
    lines = collect.build_lines(deduped)
    by = {l.names: l for l in lines}

    check("схлопнуто предсертификатов", collapsed, 12)
    check("линий сертификатов", len(lines), 5)
    check("линий с истёкшим актуальным",
          sum(1 for l in lines if l.current_expired(NOW)), 1)
    # граница включающая: линия A истекает ровно через 30 дней
    check("истекает в ближайшие 30 дней",
          sum(1 for l in lines if not l.current_expired(NOW)
              and l.days_to_expiry(NOW) is not None and l.days_to_expiry(NOW) <= 30), 2)
    check("линий с wildcard", sum(1 for l in lines if l.is_wildcard), 1)

    a = by[("a.example.com",)]
    check("выпусков в линии A", a.issuances, 12)
    check("ритм продления линии A", a.renewal_rhythm_days, 60)
    check("актуальный сертификат — последний по notBefore",
          a.current.serial, "a11")

    names = {n for l in lines for n in l.names}
    check("мусорное имя отсеяно", "not a domain" in names, False)
    check("пустое имя отсеяно", "" in names, False)

    check("Subject очищен от персональных полей",
          collect.strip_subject("C=RU, O=Aktiv, CN=ivan@x.ru, emailAddress=i@x.ru"),
          "C=RU, O=Aktiv")
