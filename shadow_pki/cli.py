"""
Запуск: сбор -> разметка -> правила -> отчёт.

    python -m shadow_pki rutoken.ru
    python -m shadow_pki rutoken.ru guardant.ru --review
    python -m shadow_pki example.ru --fixture tests/fixtures/example-company.raw.json

Экран ручного подтверждения (требования, п. 2.3) на этом шаге —
интерактивный разбор категории unknown по флагу --review. Веб-форма
делается на этапе 4.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import yaml

from . import collect, ownership as own_mod, report, rules as rules_mod

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEF_RULES = os.path.join(HERE, "config", "rules.yaml")
DEF_OWNERSHIP = os.path.join(HERE, "config", "ownership.yaml")


def log(m):
    print(m, file=sys.stderr)


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def effort_html(cfg, lines_count):
    """Раздел о трудозатратах без источника коэффициентов не выводится."""
    m = (cfg or {}).get("effort_model") or {}
    ratio = (m.get("internal_to_external_ratio") or {})
    hours = (m.get("hours_per_manual_renewal") or {})
    if not (ratio.get("value") and ratio.get("source")
            and hours.get("value") and hours.get("source")):
        return None
    total = lines_count * ratio["value"]
    per_year = total * (365 / 47)
    return (f"<p>Найдено {lines_count} линий на внешнем периметре. "
            f"При соотношении внутренних и внешних сертификатов "
            f"1:{ratio['value']} это ориентировочно {int(total)} сертификатов. "
            f"При текущем сроке жизни — около {int(per_year)} операций продления "
            f"в год, или {int(per_year * hours['value'])} человеко-часов.</p>"
            f"<p class='muted'>Источники: {ratio['source']}; {hours['source']}.</p>")


def review(lines, domain, owner):
    """Ручное подтверждение: оператор разбирает только категорию unknown."""
    unknown = [l for l in lines if l.ownership == "unknown"]
    if not unknown:
        log("Записей, требующих подтверждения, нет.")
        return []
    log(f"\nНа подтверждение: {len(unknown)} линий. "
        "[o] наша  [f] чужая  [s] пропустить  [q] закончить\n")
    decisions = []
    for i, l in enumerate(unknown, 1):
        cur = l.current
        log(f"[{i}/{len(unknown)}] {', '.join(l.names[:5])}"
            + (f" (+{len(l.names) - 5})" if len(l.names) > 5 else ""))
        log(f"        УЦ: {cur.issuer if cur else '—'} | выпусков: {l.issuances}")
        try:
            a = input("        > ").strip().lower()
        except EOFError:
            break
        if a == "q":
            break
        if a == "o":
            l.ownership, l.ownership_reason = "own", "подтверждено оператором"
            decisions.append((l.names, "own"))
        elif a == "f":
            l.ownership, l.ownership_reason = "foreign", "отклонено оператором"
            decisions.append((l.names, "foreign"))
    if decisions:
        p = owner.record_decisions(decisions, domain)
        if p:
            log(f"Решения записаны: {p}")
    return decisions


def process(domain, args, rules_cfg, own_cfg, now):
    if args.fixture:
        log(f"[{domain}] фикстура: {args.fixture}")
        with open(args.fixture, encoding="utf-8") as f:
            raw = json.load(f)
    else:
        log(f"[{domain}] запрос к {args.source}...")
        raw = collect.fetch_raw(domain, args.source, args.token)
        if args.save_raw:
            os.makedirs(args.out, exist_ok=True)
            p = os.path.join(args.out, f"{domain}.raw.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(raw, f, ensure_ascii=False)
            log(f"[{domain}] сырая выгрузка сохранена: {p}")

    certs = collect.normalize(raw, args.source)
    log(f"[{domain}] записей реестра: {len(certs)}")

    if args.months:
        cut = now - timedelta(days=30 * args.months)
        certs = [c for c in certs if (c.not_before or now) >= cut]
        log(f"[{domain}] в горизонте {args.months} мес.: {len(certs)}")

    certs, collapsed = collect.dedup_precerts(certs)
    lines = collect.build_lines(certs)
    log(f"[{domain}] линий сертификатов: {len(lines)} (схлопнуто предсертификатов: {collapsed})")

    all_names = sorted({n for l in lines for n in l.names})
    if args.no_dns:
        names_info = {n: collect.NameInfo(name=n, checked=False) for n in all_names}
        log(f"[{domain}] DNS пропущен (--no-dns)")
    else:
        log(f"[{domain}] DNS: {len(all_names)} имён...")
        names_info = collect.resolve_names(all_names)
        log(f"[{domain}] резолвится: {sum(1 for i in names_info.values() if i.resolves)}")

    owner = own_mod.Ownership(own_cfg, root_domains=[domain] + list(args.also_own))
    owner.apply(lines, names_info)
    counts = own_mod.counts(lines)
    log(f"[{domain}] принадлежность: own={counts['own']} "
        f"foreign={counts['foreign']} unknown={counts['unknown']}")

    if args.review:
        review(lines, domain, owner)
        counts = own_mod.counts(lines)

    findings, skipped = rules_mod.run(rules_cfg, lines, names_info, now)
    obs, active = rules_mod.observations(rules_cfg, lines, now)
    log(f"[{domain}] находок: {len(findings)}"
        + (f", правил не применялось: {len(skipped)}" if skipped else ""))

    scored = [l for l in lines if l.ownership == "own"]
    summary = {
        "domain": domain,
        "generated_at": now.isoformat(),
        "horizon_months": args.months,
        "source": "fixture" if args.fixture else args.source,
        "raw_ct_records": len(certs) + collapsed,
        "collapsed_precerts": collapsed,
        "certificate_lines": len(scored),
        "unique_names": len({n for l in scored for n in l.names}),
        "wildcard_lines": sum(1 for l in scored if l.is_wildcard),
        "lines_current_expired": sum(1 for l in scored if l.current_expired(now)),
        "lines_expiring_30d": sum(
            1 for l in scored if not l.current_expired(now)
            and l.days_to_expiry(now) is not None and l.days_to_expiry(now) <= 30),
        "issuers_active": active.most_common(),
        "ownership": counts,
        "findings_total": len(findings),
    }

    ctx = {
        "summary": summary,
        "findings": [f.as_dict() for f in findings],
        "skipped_rules": skipped,
        "observations": obs,
        "lines": [l.as_dict(now) for l in scored],
        "names": [names_info[n].as_dict() for n in sorted({n for l in scored for n in l.names})],
        "excluded": [{"names": list(l.names), "level": l.ownership,
                      "reason": l.ownership_reason} for l in lines if l.ownership != "own"],
    }
    ctx["effort_html"] = effort_html(rules_cfg, len(scored))

    os.makedirs(args.out, exist_ok=True)
    hp = os.path.join(args.out, f"{domain}.html")
    with open(hp, "w", encoding="utf-8") as f:
        f.write(report.render_html(ctx))
    written = [hp] + report.write_exports(ctx, args.out, domain)

    if not args.no_pdf:
        pdf, err = report.to_pdf(hp, os.path.join(args.out, f"{domain}.pdf"))
        if pdf:
            written.append(pdf)
        else:
            log(f"[{domain}] PDF не создан ({err}). HTML готов — печать из браузера.")

    for p in written:
        log(f"[{domain}] {p}")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(prog="shadow-pki-report",
                                 description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="+", help="корневые домены компании")
    ap.add_argument("--source", choices=("crtsh", "certspotter"), default="crtsh")
    ap.add_argument("--token", default=os.environ.get("CERTSPOTTER_TOKEN", ""))
    ap.add_argument("--months", type=int, default=24,
                    help="горизонт выборки, мес. (0 — без ограничения)")
    ap.add_argument("--out", default="out")
    ap.add_argument("--rules", default=DEF_RULES)
    ap.add_argument("--ownership", default=DEF_OWNERSHIP)
    ap.add_argument("--also-own", nargs="*", default=[],
                    help="дополнительные домены компании")
    ap.add_argument("--review", action="store_true",
                    help="ручное подтверждение категории unknown")
    ap.add_argument("--fixture", help="читать сырую выгрузку из файла вместо сети")
    ap.add_argument("--save-raw", action="store_true", help="сохранить сырую выгрузку")
    ap.add_argument("--no-dns", action="store_true")
    ap.add_argument("--no-pdf", action="store_true", help="только HTML")
    args = ap.parse_args(argv)

    rules_cfg = load_yaml(args.rules)
    own_cfg = load_yaml(args.ownership)
    now = datetime.now(timezone.utc)

    failed = []
    for d in args.domains:
        try:
            process(d, args, rules_cfg, own_cfg, now)
        except Exception as ex:
            log(f"[{d}] ОШИБКА: {type(ex).__name__}: {ex}")
            failed.append(d)
    if failed:
        log("\nне обработано: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
