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
import os
import sys
from datetime import datetime, timezone

import yaml

from . import pipeline

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEF_RULES = os.path.join(HERE, "config", "rules.yaml")
DEF_OWNERSHIP = os.path.join(HERE, "config", "ownership.yaml")


def log(m):
    print(m, file=sys.stderr)


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def review(run):
    """Ручное подтверждение: оператор разбирает только категорию unknown."""
    unknown = run.unknown_lines()
    if not unknown:
        log("Записей, требующих подтверждения, нет.")
        return 0
    log(f"\nНа подтверждение: {len(unknown)} линий. "
        "[o] наша  [f] чужая  [s] пропустить  [q] закончить\n")
    decisions = {}
    for i, l in enumerate(unknown):
        cur = l.current
        log(f"[{i + 1}/{len(unknown)}] {', '.join(l.names[:5])}"
            + (f" (+{len(l.names) - 5})" if len(l.names) > 5 else ""))
        log(f"        УЦ: {cur.issuer if cur else '—'} | выпусков: {l.issuances}")
        try:
            a = input("        > ").strip().lower()
        except EOFError:
            break
        if a == "q":
            break
        if a in ("o", "f"):
            decisions[i] = "own" if a == "o" else "foreign"
    return run.apply_decisions(decisions) if decisions else 0


def process(domain, args, rules_cfg, own_cfg, now):
    opts = pipeline.Options(
        source=args.source, token=args.token, months=args.months,
        also_own=tuple(args.also_own), no_dns=args.no_dns, no_pdf=args.no_pdf,
        fixture=args.fixture, save_raw=args.save_raw, out=args.out)
    run = pipeline.Run(domain=domain, opts=opts, rules_cfg=rules_cfg,
                       own_cfg=own_cfg, now=now)

    log(f"[{domain}] {'фикстура' if args.fixture else 'запрос к ' + args.source}...")
    run.collect_phase()
    for m in run.log:
        log(f"[{domain}] {m}")
    n = len(run.log)

    run.resolve_phase().mark_phase().analyze_phase()
    for m in run.log[n:]:
        log(f"[{domain}] {m}")

    if args.review:
        review(run)

    run.render_phase()
    for p in run.written:
        log(f"[{domain}] {p}")
    return run.summary()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="shadow-pki-report",
                                 description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="*", help="корневые домены компании")
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
    ap.add_argument("--serve", metavar="ПОРТ", type=int, nargs="?", const=8080,
                    help="запустить веб-интерфейс вместо разового прогона")
    args = ap.parse_args(argv)

    rules_cfg = load_yaml(args.rules)
    own_cfg = load_yaml(args.ownership)
    now = datetime.now(timezone.utc)

    if args.serve:
        from .web import serve
        return serve(args, rules_cfg, own_cfg)

    if not args.domains:
        ap.error("укажите домен или запустите с --serve")

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
