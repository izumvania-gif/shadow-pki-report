#!/usr/bin/env python3
"""
Калибровочная выгрузка из Certificate Transparency — этап 0.

Назначение: получить сырую выгрузку по домену, собрать линии сертификатов
по семантике из docs/requirements-and-plan.md п. 2.2 и показать сводку.
Нужен, чтобы разобрать реальные данные руками ДО старта разработки.

Это инструмент этапа 0, а не часть продукта. Продуктовый коллектор
пишется на этапе 1.

Принцип сбора соблюдён: обращений к хостам домена нет, только публичный
реестр CT. DNS-резолвинг сюда намеренно не включён.

Зависимости: только стандартная библиотека.

Примеры:
    python3 tools/ct_pull.py rutoken.ru
    python3 tools/ct_pull.py rutoken.ru guardant.ru --months 24 --out out/
    python3 tools/ct_pull.py rutoken.ru --source certspotter --token "$CERTSPOTTER_TOKEN"
"""

import argparse
import json
import os
import re
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

UA = "shadow-pki-report/stage0 (calibration run)"
TIMEOUT = 120

# Организационные поля Subject, которые разрешено сохранять.
# Всё остальное, включая emailAddress и CN-не-домен, отбрасывается —
# см. п. 2.8 требований (персональные данные).
SUBJECT_ALLOWED = ("O", "OU", "C", "L", "ST")

DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9_-]+\.)+[a-z]{2,}$", re.I)


def log(msg):
    print(msg, file=sys.stderr)


def fetch(url, tries=4):
    """GET с бэкоффом. Публичные CT-сервисы лимитируют запросы."""
    delay = 2
    for attempt in range(1, tries + 1):
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            # 429 и 5xx — ретраим, остальное отдаём наверх
            if e.code not in (429, 500, 502, 503, 504) or attempt == tries:
                raise
            log(f"  HTTP {e.code}, повтор через {delay}s ({attempt}/{tries})")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            if attempt == tries:
                raise
            log(f"  {type(e).__name__}, повтор через {delay}s ({attempt}/{tries})")
        time.sleep(delay)
        delay *= 2
    raise RuntimeError("недостижимо")


def parse_ts(value):
    if not value:
        return None
    v = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def norm_names(raw):
    """Нормализация перечня имён: нижний регистр, без дублей, только домены."""
    names = set()
    for n in raw:
        n = (n or "").strip().lower().rstrip(".")
        if n and DOMAIN_RE.match(n):
            names.add(n)
    return names


def strip_subject(dn):
    """Оставляем только организационные поля Subject/Issuer (п. 2.8)."""
    if not dn:
        return ""
    kept = []
    for part in re.split(r",(?=\s*[A-Za-z]+=)", dn):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        if key.strip().upper() in SUBJECT_ALLOWED:
            kept.append(f"{key.strip().upper()}={val.strip()}")
    return ", ".join(kept)


def from_crtsh(domain):
    """
    crt.sh, JSON-эндпоинт списка.

    ВАЖНО: этот эндпоинт НЕ отдаёт отпечаток публичного ключа, длину и тип
    ключа и алгоритм подписи. Требования (п. 2.1) считают отпечаток ключа
    обязательным — на нём стоит правило shared_key_unrelated_names.
    Чтобы его получить, нужен либо отдельный запрос по каждому сертификату,
    либо источник, отдающий поле сразу (см. --source certspotter).
    Это ограничение проверяется на этапе 0 и влияет на оценку этапа 1.
    """
    url = "https://crt.sh/?" + urllib.parse.urlencode(
        {"q": "%." + domain, "output": "json"}
    )
    rows = fetch(url)
    out = []
    for r in rows:
        names = norm_names(str(r.get("name_value", "")).split("\n"))
        cn = (r.get("common_name") or "").strip().lower()
        if cn and DOMAIN_RE.match(cn):
            names.add(cn)
        out.append(
            {
                "source_id": r.get("id"),
                "issuer": strip_subject(r.get("issuer_name")),
                "issuer_raw_ca_id": r.get("issuer_ca_id"),
                "serial": (r.get("serial_number") or "").lower(),
                "not_before": r.get("not_before"),
                "not_after": r.get("not_after"),
                "names": sorted(names),
                "pubkey_sha256": None,  # crt.sh список не отдаёт
                "key_alg": None,
                "key_size": None,
                "sig_alg": None,
            }
        )
    return out


def from_certspotter(domain, token):
    """
    Cert Spotter API. Отдаёт pubkey_sha256 сразу, поэтому годится там,
    где нужен отпечаток ключа. Требует токен, лимиты на бесплатном тарифе
    жёстче. Проверить объём и лимиты — задача этапа 0.
    """
    base = "https://api.certspotter.com/v1/issuances"
    params = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": ["dns_names", "issuer", "cert"],
        "match_wildcards": "true",
    }
    out, after = [], None
    while True:
        q = [("domain", domain), ("include_subdomains", "true"),
             ("match_wildcards", "true")]
        for e in params["expand"]:
            q.append(("expand", e))
        if after:
            q.append(("after", after))
        url = base + "?" + urllib.parse.urlencode(q)
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        if token:
            req.add_header("Authorization", "Bearer " + token)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            rows = json.loads(r.read().decode("utf-8", "replace"))
        if not rows:
            break
        for r in rows:
            cert = r.get("cert") or {}
            issuer = r.get("issuer") or {}
            out.append(
                {
                    "source_id": r.get("id"),
                    "issuer": strip_subject(issuer.get("name")),
                    "issuer_raw_ca_id": issuer.get("pubkey_sha256"),
                    "serial": "",
                    "not_before": r.get("not_before"),
                    "not_after": r.get("not_after"),
                    "names": sorted(norm_names(r.get("dns_names") or [])),
                    "pubkey_sha256": cert.get("pubkey_sha256"),
                    "key_alg": None,
                    "key_size": None,
                    "sig_alg": None,
                }
            )
        after = rows[-1].get("id")
        if not after:
            break
        time.sleep(1)
    return out


def dedup_precerts(certs):
    """
    Схлопывание предсертификата и конечного сертификата (п. 2.1).
    Пара делит издателя и серийный номер. Если серийника нет — падаем
    на пару (издатель, набор имён, notBefore).
    """
    seen, out, collapsed = {}, [], 0
    for c in certs:
        if c["serial"]:
            key = (c["issuer_raw_ca_id"], c["serial"])
        else:
            key = (c["issuer_raw_ca_id"], tuple(c["names"]), c["not_before"])
        if key in seen:
            collapsed += 1
            # предпочитаем запись, где больше заполненных полей
            prev = seen[key]
            if c.get("pubkey_sha256") and not prev.get("pubkey_sha256"):
                out[out.index(prev)] = c
                seen[key] = c
            continue
        seen[key] = c
        out.append(c)
    return out, collapsed


def build_lines(certs, now):
    """
    Сборка линий сертификатов (п. 2.2).
    Ключ группировки — нормализованный набор SAN.
    """
    groups = defaultdict(list)
    for c in certs:
        groups[tuple(c["names"])].append(c)

    lines = []
    for names, items in groups.items():
        items.sort(key=lambda c: parse_ts(c["not_before"]) or datetime.min.replace(tzinfo=timezone.utc))
        current = items[-1]
        starts = [parse_ts(c["not_before"]) for c in items if parse_ts(c["not_before"])]
        gaps = [
            (b - a).days for a, b in zip(starts, starts[1:]) if (b - a).days > 0
        ]
        na = parse_ts(current["not_after"])
        lines.append(
            {
                "names": list(names),
                "issuances": len(items),
                "issuers": sorted({c["issuer"] for c in items if c["issuer"]}),
                "current": current,
                "current_expired": bool(na and na < now),
                "days_to_expiry": (na - now).days if na else None,
                "renewal_rhythm_days": int(statistics.median(gaps)) if gaps else None,
                "is_wildcard": any(n.startswith("*.") for n in names),
            }
        )
    lines.sort(key=lambda l: (-l["issuances"], l["names"][0] if l["names"] else ""))
    return lines


def summarize(domain, certs, lines, collapsed, now, months):
    active_issuers = Counter()
    for l in lines:
        if not l["current_expired"] and l["current"]["issuer"]:
            active_issuers[l["current"]["issuer"]] += 1

    all_names = sorted({n for l in lines for n in l["names"]})
    expired = [l for l in lines if l["current_expired"]]
    soon30 = [l for l in lines
              if not l["current_expired"]
              and l["days_to_expiry"] is not None and l["days_to_expiry"] <= 30]
    rhythms = [l["renewal_rhythm_days"] for l in lines if l["renewal_rhythm_days"]]

    return {
        "domain": domain,
        "generated_at": now.isoformat(),
        "horizon_months": months,
        "raw_ct_records": len(certs) + collapsed,
        "collapsed_precerts": collapsed,
        "certificates_after_dedup": len(certs),
        "certificate_lines": len(lines),
        "unique_names": len(all_names),
        "wildcard_lines": sum(1 for l in lines if l["is_wildcard"]),
        "lines_current_expired": len(expired),
        "lines_expiring_30d": len(soon30),
        "issuers_active": active_issuers.most_common(),
        "issuers_ever": Counter(
            i for l in lines for i in l["issuers"]
        ).most_common(),
        "median_renewal_days": int(statistics.median(rhythms)) if rhythms else None,
        "names": all_names,
    }


def print_summary(s):
    print()
    print("=" * 68)
    print(f"  {s['domain']}   горизонт {s['horizon_months']} мес.")
    print("=" * 68)
    print(f"  Записей в CT (сырых)          {s['raw_ct_records']:>6}")
    print(f"  Схлопнуто предсертификатов    {s['collapsed_precerts']:>6}")
    print(f"  Сертификатов после дедупа     {s['certificates_after_dedup']:>6}")
    print(f"  ЛИНИЙ сертификатов            {s['certificate_lines']:>6}   <- это число идёт в отчёт")
    print(f"  Уникальных имён               {s['unique_names']:>6}")
    print(f"  Линий с wildcard              {s['wildcard_lines']:>6}")
    print()
    print(f"  Актуальный сертификат истёк   {s['lines_current_expired']:>6}")
    print(f"  Истекает в ближайшие 30 дней  {s['lines_expiring_30d']:>6}")
    if s["median_renewal_days"]:
        print(f"  Медианный ритм продления      {s['median_renewal_days']:>6} дней")
    print()
    ratio = (s["raw_ct_records"] / s["certificate_lines"]) if s["certificate_lines"] else 0
    print(f"  Коэффициент завышения без группировки: x{ratio:.1f}")
    print(f"  (столько раз соврал бы отчёт, считая записи CT вместо линий)")
    print()
    print("  УЦ с действующими сертификатами:")
    for issuer, n in s["issuers_active"][:10]:
        print(f"    {n:>4}  {issuer[:60]}")
    if len(s["issuers_ever"]) > len(s["issuers_active"]):
        print(f"  Всего УЦ встречалось за период: {len(s['issuers_ever'])}"
              f" (мультивендорность считается только по действующим)")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="+", help="корневые домены")
    ap.add_argument("--source", choices=("crtsh", "certspotter"), default="crtsh")
    ap.add_argument("--token", default=os.environ.get("CERTSPOTTER_TOKEN", ""),
                    help="токен для certspotter")
    ap.add_argument("--months", type=int, default=24,
                    help="горизонт выборки по notBefore, мес. (0 — без ограничения)")
    ap.add_argument("--out", default="out", help="каталог для JSON-выгрузки")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30 * args.months) if args.months else None
    os.makedirs(args.out, exist_ok=True)
    failed = []

    for domain in args.domains:
        log(f"[{domain}] запрос к {args.source}...")
        try:
            if args.source == "crtsh":
                certs = from_crtsh(domain)
            else:
                certs = from_certspotter(domain, args.token)
        except Exception as e:
            log(f"[{domain}] ОШИБКА: {type(e).__name__}: {e}")
            failed.append(domain)
            continue

        log(f"[{domain}] получено записей: {len(certs)}")
        if cutoff:
            certs = [c for c in certs
                     if (parse_ts(c["not_before"]) or now) >= cutoff]
            log(f"[{domain}] после горизонта {args.months} мес.: {len(certs)}")

        certs, collapsed = dedup_precerts(certs)
        lines = build_lines(certs, now)
        summary = summarize(domain, certs, lines, collapsed, now, args.months)
        print_summary(summary)

        path = os.path.join(args.out, f"{domain}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "lines": lines}, f,
                      ensure_ascii=False, indent=2, default=str)
        log(f"[{domain}] выгрузка: {path}")

    if failed:
        log(f"\nне удалось получить данные: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
