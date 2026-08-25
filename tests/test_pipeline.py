"""Сквозной прогон на фикстуре: от сырой выгрузки до отчёта."""

import json
import os
import tempfile
from datetime import datetime, timezone

from shadow_pki import cli

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "example-company.raw.json")


class Args:
    source = "crtsh"; token = ""; months = 24
    rules = cli.DEF_RULES; ownership = cli.DEF_OWNERSHIP
    also_own = []; review = False; save_raw = False
    no_dns = True          # без сети, чтобы результат был детерминированным
    no_pdf = False
    fixture = FIXTURE


def run(check):
    with tempfile.TemporaryDirectory() as td:
        args = Args(); args.out = td
        cli.process("example.com", args, cli.load_yaml(args.rules),
                    cli.load_yaml(args.ownership), datetime.now(timezone.utc))
        with open(os.path.join(td, "example.com.json"), encoding="utf-8") as f:
            ctx = json.load(f)
        raw = open(os.path.join(td, "example.com.html"), encoding="utf-8").read()
        html = " ".join(raw.split())   # переносы строк не должны ломать проверку
        files = sorted(os.listdir(td))

    s = ctx["summary"]
    ids = {f["rule_id"] for f in ctx["findings"]}
    skipped = {r["id"] for r in ctx["skipped_rules"]}
    excluded = {x["level"] for x in ctx["excluded"]}

    check("74 записи реестра сведены в линии", s["raw_ct_records"], 72)
    check("предсертификаты схлопнуты", s["collapsed_precerts"], 36)
    check("CDN ушёл в foreign", "foreign" in excluded, True)
    check("чужой домен ушёл в unknown", "unknown" in excluded, True)
    check("unknown не попадает в находки", s["ownership"]["unknown"] > 0, True)

    check("найдено истечение через 7 дней", "expiring_7d" in ids, True)
    check("найден непереывпущенный", "line_expired_not_reissued" in ids, True)
    check("найден широкий wildcard", "wildcard_broad" in ids, True)
    check("найдены служебные имена", "nonprod_name_exposed" in ids, True)

    check("правило без поля источника пропущено",
          "shared_key_unrelated_names" in skipped, True)
    check("правило без корпоративного стандарта пропущено",
          "issuance_unattributed" in skipped, True)
    check("пропущенные правила не дают находок", ids & skipped, set())

    check("находок не больше числа линий втрое",
          len(ctx["findings"]) <= s["certificate_lines"] * 3, True)

    check("методология в отчёте", "обращений не производилось" in html, True)
    check("формулировка о факте выпуска", "факт выпуска" in html, True)
    check("раздел трудозатрат без источника не выводится",
          "Раздел не выводится" in html or "не подкреплены источником" in html, True)

    for want in ("example.com.html", "example.com.json", "example.com.pdf",
                 "example.com.certificates.csv", "example.com.findings.csv"):
        check(f"создан {want}", want in files, True)
