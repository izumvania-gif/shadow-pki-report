"""
Движок правил (требования, п. 2.4).

Правила декларативны и применяются к линиям, именам и ключам.
Тот же конфиг переиспользуется в Рутокен CLM без переписывания —
поэтому вся логика находится здесь, а формулировки в YAML.
"""

import re
from collections import Counter, defaultdict

from .model import Finding, registrable

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _predicate(ctx, key, want):
    """Один предикат условия. Суффикс определяет операцию."""
    for suffix, op in (
        ("_lte", lambda a, b: a is not None and a <= b),
        ("_lt", lambda a, b: a is not None and a < b),
        ("_gte", lambda a, b: a is not None and a >= b),
        ("_gt", lambda a, b: a is not None and a > b),
        ("_in", lambda a, b: a in b),
    ):
        if key.endswith(suffix):
            return op(ctx.get(key[: -len(suffix)]), want)
    if key == "name_matches_any":
        name = ctx.get("name") or ""
        return any(re.search(p, name, re.I) for p in want)
    return ctx.get(key) == want


def evaluate(condition, ctx):
    if not condition:
        return True
    if "all" in condition:
        return all(evaluate(c, ctx) for c in condition["all"])
    if "any" in condition:
        return any(evaluate(c, ctx) for c in condition["any"])
    return all(_predicate(ctx, k, v) for k, v in condition.items())


def _fmt(template, ctx):
    class Safe(dict):
        def __missing__(self, k):
            return "—"
    return " ".join((template or "").format_map(Safe(ctx)).split())


def line_ctx(line, names_info, now, known_processes):
    cur = line.current
    resolving = [n for n in line.names
                 if names_info.get(n) and names_info[n].resolves]
    na = cur.not_after if cur else None
    return {
        "name": line.names[0] if line.names else "",
        "names": ", ".join(line.names[:8]) + ("…" if len(line.names) > 8 else ""),
        "count": len(line.names),
        "covered_names": len(line.names),
        "issuer": (cur.issuer if cur else "") or "неизвестный УЦ",
        "issuers": ", ".join(line.issuers_ever),
        "current_expired": line.current_expired(now),
        "any_name_resolves": bool(resolving),
        "days_to_expiry": line.days_to_expiry(now),
        "days": line.days_to_expiry(now),
        "expired_at": na.strftime("%d.%m.%Y") if na else "—",
        "key_alg": cur.key_alg if cur else None,
        "key_size": cur.key_size if cur else None,
        "sig_alg": cur.sig_alg if cur else None,
        "is_wildcard": line.is_wildcard,
        "rhythm": line.renewal_rhythm_days,
        "provider_attributed": bool(line.provider),
        "matches_known_process": bool(
            cur and any(re.search(p, cur.issuer or "", re.I) for p in known_processes)),
    }


def name_ctx(info, has_cert):
    return {"name": info.name, "resolves": info.resolves,
            "has_certificate": has_cert, "count": 1}


def key_ctx(pubkey, lines):
    names = sorted({n for l in lines for n in l.names})
    return {"name": names[0] if names else "",
            "names": ", ".join(names[:8]) + ("…" if len(names) > 8 else ""),
            "count": len(names),
            "distinct_registrable_domains": len({registrable(n) for n in names})}


def _field_present(rule, lines):
    """requires_field: правило не применяется, если источник поля не отдал."""
    f = rule.get("requires_field")
    if not f:
        return True
    return any(getattr(l.current, f, None) for l in lines if l.current)


def _config_present(rule, cfg):
    """
    requires_config: правило не применяется, пока не задана настройка,
    без которой оно не имеет смысла.

    Так закрыт issuance_unattributed: без списка УЦ корпоративного
    стандарта «источник не идентифицирован» истинно для КАЖДОГО выпуска,
    и правило пометило бы весь домен. Отчёт с находкой на каждой строке
    читается как непонимание инфраструктуры.
    """
    key = rule.get("requires_config")
    if not key:
        return True
    node = cfg
    for part in key.split("."):
        node = (node or {}).get(part) if isinstance(node, dict) else None
    return bool(node)


def run(cfg, lines, names_info, now, known_processes=None):
    """
    Возвращает (findings, skipped_rules).

    skipped_rules — правила, не применявшиеся из-за отсутствия полей в
    источнике. Они выносятся в методологию отчёта: молчаливый пропуск
    правила означает, что отчёт заявляет проверку, которой не было.
    """
    findings, skipped = [], []
    scored = [l for l in lines if l.ownership == "own"]
    if known_processes is None:
        known_processes = ((cfg.get("corporate_standard") or {})
                           .get("known_ca_patterns") or [])

    by_key = defaultdict(list)
    for l in scored:
        if l.current and l.current.pubkey_sha256:
            by_key[l.current.pubkey_sha256].append(l)

    named = {}
    for l in scored:
        for n in l.names:
            named.setdefault(n, names_info.get(n))

    for rule in cfg.get("findings", []):
        if not _field_present(rule, scored):
            skipped.append({"id": rule["id"], "title": rule["title"],
                            "reason": f"источник не отдал поле {rule['requires_field']}"})
            continue
        if not _config_present(rule, cfg):
            skipped.append({"id": rule["id"], "title": rule["title"],
                            "reason": f"не задана настройка {rule['requires_config']}"})
            continue

        target = rule.get("applies_to")
        if target == "line":
            items = [(l, line_ctx(l, names_info, now, known_processes)) for l in scored]
        elif target == "name":
            items = [(i, name_ctx(i, True)) for i in named.values() if i]
        elif target == "key":
            items = [(ls, key_ctx(k, ls)) for k, ls in by_key.items() if len(ls) > 1]
        else:
            continue

        matched = [ctx for _, ctx in items if evaluate(rule.get("condition"), ctx)]
        if not matched:
            continue

        if rule.get("aggregate"):
            # Однотипные срабатывания сводятся в одну находку. Иначе один
            # wildcard с полусотней имён в SAN даёт полсотни строк отчёта
            # и вытесняет всё остальное.
            subjects = sorted({c.get("name", "") for c in matched if c.get("name")})
            ctx = {"count": len(subjects),
                   "name": subjects[0] if subjects else "",
                   "names": ", ".join(subjects[:12]) + ("…" if len(subjects) > 12 else "")}
            findings.append(Finding(
                rule_id=rule["id"], severity=rule["severity"], title=rule["title"],
                text=_fmt(rule.get("finding_aggregated") or rule.get("finding"), ctx),
                recommendation=_fmt(rule.get("recommendation"), ctx),
                subject=f"{len(subjects)} имён"))
            continue

        for ctx in matched:
            findings.append(Finding(
                rule_id=rule["id"],
                severity=rule["severity"],
                title=rule["title"],
                text=_fmt(rule.get("finding"), ctx),
                recommendation=_fmt(rule.get("recommendation"), ctx),
                subject=ctx.get("names") or ctx.get("name", ""),
            ))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id))
    return findings, skipped


def observations(cfg, lines, now):
    scored = [l for l in lines if l.ownership == "own"]
    active = Counter()
    for l in scored:
        if not l.current_expired(now) and l.current and l.current.issuer:
            active[l.current.issuer] += 1
    rhythms = [l.renewal_rhythm_days for l in scored if l.renewal_rhythm_days]
    provider_lines = sum(1 for l in lines if l.provider)
    rhythm = int(sorted(rhythms)[len(rhythms) // 2]) if rhythms else None

    ctx = {
        "obs_provider_issuance": {"count": provider_lines},
        "obs_active_ca_count": {"count": len(active),
                                "issuers": ", ".join(i for i, _ in active.most_common(8))},
        "obs_renewal_rhythm": {"rhythm": rhythm},
    }
    out = []
    for obs in cfg.get("observations", []):
        c = ctx.get(obs["id"], {})
        if not c or all(v in (None, 0, "") for v in c.values()):
            continue
        out.append({"title": obs["title"], "text": _fmt(obs.get("text"), c)})
    return out, active
