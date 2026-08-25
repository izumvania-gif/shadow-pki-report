"""
Правила: проверки, вытекающие из разбора реальной выгрузки.

Ключевой случай — имя, покрытое действующим сертификатом из соседней
линии. Линии группируются по набору SAN, поэтому имя с менявшимся
составом SAN попадает в несколько линий, и старая линия выглядит
истёкшей. На реальном домене крупного банка это дало 88 находок
уровня «критично», включая «*.<домен> истёк» при исправном продлении.
"""

from datetime import datetime, timezone, timedelta

from shadow_pki import collect, rules as rules_mod
from shadow_pki.cli import load_yaml, DEF_RULES
from shadow_pki.model import Cert, NameInfo, norm_names

NOW = datetime(2026, 8, 25, tzinfo=timezone.utc)


def cert(names, serial, nb_days_ago, valid_days, issuer="CA-Test"):
    nb = NOW - timedelta(days=nb_days_ago)
    return Cert(issuer=issuer, issuer_key=issuer, serial=serial,
                not_before=nb, not_after=nb + timedelta(days=valid_days),
                names=tuple(sorted(norm_names(names))))


def analyze(certs, resolving=(), roots=("example.com",)):
    lines = collect.build_lines(certs)
    for l in lines:
        l.ownership = "own"
    info = {}
    for l in lines:
        for n in l.names:
            info[n] = NameInfo(name=n, checked=True, resolves=n in resolving,
                               addresses=("192.0.2.1",) if n in resolving else ())
    cfg = load_yaml(DEF_RULES)
    findings, _ = rules_mod.run(cfg, lines, info, NOW)
    return lines, findings


def run(check):
    # --- случай из реальной выгрузки -----------------------------------
    # Состав SAN менялся: сначала сертификат на одно имя, потом на два.
    # Старая линия истекла, но имя покрыто действующим сертификатом.
    certs = [
        cert(["a.example.com"], "old", 400, 90),                    # истёк
        cert(["a.example.com", "b.example.com"], "new", 10, 365),   # действует
    ]
    lines, findings = analyze(certs, resolving=("a.example.com", "b.example.com"))
    check("SAN изменился -> две линии", len(lines), 2)
    expired_rules = {"name_resolves_cert_expired", "line_expired_not_reissued"}
    got = {f["rule_id"] if isinstance(f, dict) else f.rule_id for f in findings}
    check("имя, покрытое действующим сертификатом, не считается истёкшим",
          bool(got & expired_rules), False)

    # то же для wildcard — именно он выглядел хуже всего в отчёте
    certs = [
        cert(["*.example.com"], "w-old", 500, 365),
        cert(["*.example.com", "example.com"], "w-new", 20, 365),
    ]
    _, findings = analyze(certs, resolving=("*.example.com", "example.com"))
    got = {f.rule_id for f in findings}
    check("wildcard, перевыпущенный с расширенным SAN, не помечается истёкшим",
          bool(got & expired_rules), False)

    # --- истёкшее по-настоящему всё ещё находится ------------------------
    certs = [
        cert(["gone.example.com"], "g1", 500, 90),
        cert(["live.example.com"], "l1", 10, 365),
    ]
    _, findings = analyze(certs, resolving=("gone.example.com",))
    got = {f.rule_id for f in findings}
    check("действительно непокрытое имя по-прежнему находится",
          "name_resolves_cert_expired" in got, True)

    certs = [cert(["forgotten.example.com"], "f1", 600, 90)]
    _, findings = analyze(certs, resolving=())
    got = {f.rule_id for f in findings}
    check("забытое нерезолвящееся имя по-прежнему находится",
          "line_expired_not_reissued" in got, True)

    # --- покрытие считается только по своим записям ----------------------
    live = rules_mod.live_coverage(
        collect.build_lines([cert(["x.example.com"], "x1", 5, 365)]), NOW)
    check("действующее имя попало в карту покрытия", "x.example.com" in live, True)
    live = rules_mod.live_coverage(
        collect.build_lines([cert(["y.example.com"], "y1", 500, 90)]), NOW)
    check("истёкшее имя в карту покрытия не попало", "y.example.com" in live, False)


def run_input(check):
    """Нормализация ввода и признаки неполной выгрузки."""
    from shadow_pki.model import normalize_root
    check("www снимается", normalize_root("www.sdm.ru"), ("sdm.ru", True))
    check("корневой домен не трогаем", normalize_root("SDM.ru."), ("sdm.ru", False))
    check("wwwx не считается префиксом", normalize_root("wwwx.ru"), ("wwwx.ru", False))

    from shadow_pki.pipeline import Run, Options
    r = Run(domain="x.ru", opts=Options(), rules_cfg={}, own_cfg={}, now=NOW)
    r.certs = [cert(["a.x.ru"], "1", 10, 90)]
    r.collapsed = 0
    r.check_plausibility()
    check("отсутствие предсертификатов помечено",
          any("предсертификаты" in w for w in r.warnings), True)
    check("малый объём выборки помечен",
          any("неправдоподобно мало" in w for w in r.warnings), True)

    r2 = Run(domain="x.ru", opts=Options(), rules_cfg={}, own_cfg={}, now=NOW)
    r2.certs = [cert([f"n{i}.x.ru"], str(i), 10, 90) for i in range(40)]
    r2.collapsed = 40
    r2.check_plausibility()
    check("нормальная выгрузка замечаний не даёт", r2.warnings, [])
