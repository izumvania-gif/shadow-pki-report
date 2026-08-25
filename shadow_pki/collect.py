"""
Сбор из публичных реестров.

Принцип сбора (требования, п. 1): обращений к хостам компании нет.
Запросы уходят только к API логов Certificate Transparency и к публичным
DNS-резолверам. Кода, устанавливающего соединение с найденным именем,
в этом модуле быть не должно — см. tests/test_no_host_contact.py.
"""

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .model import Cert, Line, NameInfo, norm_names

UA = "shadow-pki-report/0.1 (public registries only)"
TIMEOUT = 120

# Организационные поля Subject, которые разрешено сохранять.
# Всё остальное отбрасывается при разборе — п. 2.8 требований.
SUBJECT_ALLOWED = ("O", "OU", "C", "L", "ST")

# Хосты, к которым модулю разрешено обращаться. Проверяется тестом.
ALLOWED_HOSTS = ("crt.sh", "api.certspotter.com")


def parse_ts(v):
    if not v:
        return None
    s = str(v).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def strip_subject(dn):
    """Оставляем только организационные поля (п. 2.8, персональные данные)."""
    if not dn:
        return ""
    kept = []
    for part in re.split(r",(?=\s*[A-Za-z]+=)", dn):
        key, _, val = part.strip().partition("=")
        if val and key.strip().upper() in SUBJECT_ALLOWED:
            kept.append(f"{key.strip().upper()}={val.strip()}")
    return ", ".join(kept)


def _get(url, headers=None, tries=4):
    delay = 2
    for attempt in range(1, tries + 1):
        req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == tries:
                raise
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            if attempt == tries:
                raise
        time.sleep(delay)
        delay *= 2


def fetch_raw(domain, source="crtsh", token=""):
    """Сырая выгрузка из CT. Возвращает список записей источника как есть."""
    if source == "crtsh":
        url = "https://crt.sh/?" + urllib.parse.urlencode(
            {"q": "%." + domain, "output": "json"})
        return _get(url)

    rows, after = [], None
    while True:
        q = [("domain", domain), ("include_subdomains", "true"),
             ("match_wildcards", "true"), ("expand", "dns_names"),
             ("expand", "issuer"), ("expand", "cert")]
        if after:
            q.append(("after", after))
        page = _get("https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(q),
                    headers={"Authorization": "Bearer " + token} if token else None)
        if not page:
            break
        rows.extend(page)
        after = page[-1].get("id")
        if not after:
            break
        time.sleep(1)
    return rows


def normalize(rows, source="crtsh"):
    """Сырые записи источника -> Cert. Персональные поля Subject отброшены."""
    out = []
    for r in rows:
        if source == "crtsh":
            names = norm_names(str(r.get("name_value", "")).split("\n"))
            names |= norm_names([r.get("common_name") or ""])
            out.append(Cert(
                source_id=r.get("id"),
                issuer=strip_subject(r.get("issuer_name")),
                issuer_key=str(r.get("issuer_ca_id")),
                serial=(r.get("serial_number") or "").lower(),
                not_before=parse_ts(r.get("not_before")),
                not_after=parse_ts(r.get("not_after")),
                names=tuple(sorted(names)),
                # crt.sh в списочном эндпоинте эти поля не отдаёт.
                pubkey_sha256=None, key_alg=None, key_size=None, sig_alg=None,
            ))
        else:
            cert = r.get("cert") or {}
            issuer = r.get("issuer") or {}
            out.append(Cert(
                source_id=r.get("id"),
                issuer=strip_subject(issuer.get("name")),
                issuer_key=str(issuer.get("pubkey_sha256")),
                serial="",
                not_before=parse_ts(r.get("not_before")),
                not_after=parse_ts(r.get("not_after")),
                names=tuple(sorted(norm_names(r.get("dns_names") or []))),
                pubkey_sha256=cert.get("pubkey_sha256"),
                key_alg=cert.get("key_algorithm"),
                key_size=cert.get("key_size"),
                sig_alg=cert.get("signature_algorithm"),
            ))
    return out


def dedup_precerts(certs):
    """Предсертификат и конечный сертификат — одна запись (п. 2.1)."""
    seen, out, collapsed = {}, [], 0
    for c in certs:
        key = ((c.issuer_key, c.serial) if c.serial
               else (c.issuer_key, c.names, c.not_before))
        if key in seen:
            collapsed += 1
            prev = seen[key]
            if c.pubkey_sha256 and not prev.pubkey_sha256:
                out[out.index(prev)] = c
                seen[key] = c
            continue
        seen[key] = c
        out.append(c)
    return out, collapsed


def build_lines(certs):
    """Группировка выпусков в линии по набору SAN (п. 2.2)."""
    groups = {}
    for c in certs:
        groups.setdefault(c.names, Line(names=c.names)).certs.append(c)
    lines = list(groups.values())
    for l in lines:
        l.sort()
    lines.sort(key=lambda l: (-l.issuances, l.names[0] if l.names else ""))
    return lines


def resolve_names(names, workers=16):
    """
    Публичный DNS. Запрос уходит к резолверу, а не к хосту имени:
    getaddrinfo только разрешает имя и соединения не открывает.
    """
    def one(name):
        info = NameInfo(name=name, checked=True)
        target = name[2:] if name.startswith("*.") else name
        try:
            res = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
            info.addresses = tuple(sorted({r[4][0] for r in res}))
            info.resolves = bool(info.addresses)
        except (socket.gaierror, UnicodeError, OSError):
            info.resolves = False
        return info

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return {i.name: i for i in pool.map(one, names)}
