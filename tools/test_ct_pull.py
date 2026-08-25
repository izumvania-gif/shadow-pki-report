#!/usr/bin/env python3
"""
Проверка семантики линии сертификата (docs/requirements-and-plan.md п. 2.2)
на синтетических данных. Запуск: python3 tools/test_ct_pull.py

Смысл теста — зафиксировать то, что в требованиях названо единственной
жёсткой зависимостью плана: что считается линией, что актуальным
сертификатом и какое число идёт в отчёт.
"""
import sys
from datetime import datetime, timezone, timedelta
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import ct_pull as m

NOW = datetime(2026, 8, 25, tzinfo=timezone.utc)


def cert(names, issuer, serial, nb, na):
    return {"source_id": serial, "issuer": issuer, "issuer_raw_ca_id": issuer,
            "serial": serial, "not_before": nb.isoformat(), "not_after": na.isoformat(),
            "names": sorted(m.norm_names(names)), "pubkey_sha256": None,
            "key_alg": None, "key_size": None, "sig_alg": None}


def build():
    certs = []
    # A: 12 автопродлений раз в 60 дней, каждое продублировано предсертификатом
    for i in range(12):
        nb = NOW - timedelta(days=60 * (12 - i))
        certs += [cert(["a.example.ru"], "CA-Free", f"a{i}", nb, nb + timedelta(days=90))] * 2
    # B: истекла и не перевыпущена
    nb = NOW - timedelta(days=500)
    certs.append(cert(["old.example.ru"], "CA-Comm", "b1", nb, nb + timedelta(days=365)))
    # C: истекает через 12 дней, УЦ отличается от остальных
    nb = NOW - timedelta(days=78)
    certs.append(cert(["c.example.ru"], "CA-Other", "c1", nb, nb + timedelta(days=90)))
    # D: wildcard
    nb = NOW - timedelta(days=10)
    certs.append(cert(["*.example.ru", "example.ru"], "CA-Comm", "d1", nb, nb + timedelta(days=365)))
    # E: мусорные значения в SAN должны отсеяться
    certs.append(cert(["not a domain", "", "e.example.ru"], "CA-Comm", "e1", nb, nb + timedelta(days=90)))
    return certs


def main():
    deduped, collapsed = m.dedup_precerts(build())
    lines = m.build_lines(deduped, NOW)
    s = m.summarize("example.ru", deduped, lines, collapsed, NOW, 24)

    checks = [
        ("схлопнуто предсертификатов", collapsed, 12),
        ("линий сертификатов", s["certificate_lines"], 5),
        ("актуальный сертификат истёк", s["lines_current_expired"], 1),
        # линия C (12 дней) и линия A (ровно 30 дней) — граница включающая
        ("истекает в ближайшие 30 дней", s["lines_expiring_30d"], 2),
        ("линий с wildcard", s["wildcard_lines"], 1),
        ("УЦ с действующими сертификатами", len(s["issuers_active"]), 3),
    ]
    A = [l for l in lines if l["names"] == ["a.example.ru"]][0]
    checks += [
        ("выпусков в линии A", A["issuances"], 12),
        ("ритм продления линии A, дней", A["renewal_rhythm_days"], 60),
    ]

    failed = 0
    for label, got, want in checks:
        ok = got == want
        failed += not ok
        print(f"  {'ok ' if ok else 'FAIL'}  {label}: {got}" + ("" if ok else f" (ожидалось {want})"))

    for bad in ("not a domain", ""):
        ok = bad not in s["names"]
        failed += not ok
        print(f"  {'ok ' if ok else 'FAIL'}  мусорное имя {bad!r} отсеяно")

    # персональные поля Subject не должны сохраняться (п. 2.8)
    got = m.strip_subject("C=RU, O=Aktiv, CN=ivan.petrov@example.ru, emailAddress=ivan@example.ru")
    ok = got == "C=RU, O=Aktiv"
    failed += not ok
    print(f"  {'ok ' if ok else 'FAIL'}  Subject очищен от персональных полей: {got!r}")

    ratio = s["raw_ct_records"] / s["certificate_lines"]
    print(f"\n  28 записей CT -> 5 линий. Без группировки отчёт завысил бы счёт в {ratio:.1f} раза.")
    print("\n" + ("ПРОВАЛЕНО проверок: %d" % failed if failed else "ВСЕ ПРОВЕРКИ ПРОШЛИ"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
