"""
Трёхуровневая разметка принадлежности (требования, п. 2.3).

own      — принадлежность подтверждена, идёт в отчёт
foreign  — атрибутировано внешнему владельцу, исключается с причиной
unknown  — правило не сработало, выносится на ручное подтверждение

Умолчание — unknown. Исключённое не удаляется: причина сохраняется,
чтобы можно было проверить, не выкинули ли лишнего.
"""

import json
import os
import re

from .model import registrable


def _any_match(patterns, *texts):
    for p in patterns or []:
        rx = re.compile(p, re.I)
        for t in texts:
            if t and rx.search(t):
                return p
    return None


class Ownership:
    def __init__(self, cfg, root_domains=None):
        self.cfg = cfg or {}
        own = self.cfg.get("own") or {}
        self.roots = [d.lower() for d in (root_domains or own.get("root_domains") or [])]
        self.foreign = self.cfg.get("foreign") or {}
        self.log_path = self.cfg.get("operator_decisions_log")

    def _in_roots(self, name):
        n = name.lstrip("*.").lower()
        return any(n == r or n.endswith("." + r) for r in self.roots)

    def mark(self, line, names_info):
        """Проставляет line.ownership / ownership_reason / provider."""
        cur = line.current
        issuer = cur.issuer if cur else ""
        cnames = [ (names_info.get(n).cname or "") for n in line.names
                   if names_info.get(n) ]

        prov = self.foreign.get("infrastructure_providers") or {}
        hit = _any_match(prov.get("match_issuer_or_cname_any"), issuer, *cnames)
        if hit:
            line.ownership = "foreign"
            line.provider = hit
            line.ownership_reason = prov.get("reason", "инфраструктурный провайдер")
            return line

        saas = self.foreign.get("saas_on_subdomain") or {}
        hit = _any_match(saas.get("match_cname_any"), *cnames)
        if hit:
            line.ownership = "foreign"
            line.provider = hit
            line.ownership_reason = saas.get("reason", "сторонний SaaS")
            return line

        omni = self.foreign.get("omni_san") or {}
        regs = {registrable(n) for n in line.names}
        if regs and len(regs) >= (omni.get("distinct_registrable_domains_gte") or 10**9):
            ours = sum(1 for r in regs if r in self.roots)
            if ours / len(regs) <= (omni.get("company_share_lte") or 0):
                line.ownership = "foreign"
                line.ownership_reason = omni.get("reason", "общий сертификат провайдера")
                return line

        if self.roots and all(self._in_roots(n) for n in line.names):
            line.ownership = "own"
            line.ownership_reason = "все имена в корневых доменах компании"
        else:
            line.ownership = "unknown"
            line.ownership_reason = "правило не сработало, нужно подтверждение"
        return line

    def apply(self, lines, names_info):
        for l in lines:
            self.mark(l, names_info)
        return lines

    def record_decisions(self, decisions, domain):
        """Решения оператора — обучающая выборка для автоматизации фильтра."""
        if not self.log_path or not decisions:
            return None
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            for names, decision in decisions:
                f.write(json.dumps(
                    {"domain": domain, "names": list(names), "decision": decision},
                    ensure_ascii=False) + "\n")
        return self.log_path


def counts(lines):
    c = {"own": 0, "foreign": 0, "unknown": 0}
    for l in lines:
        c[l.ownership] = c.get(l.ownership, 0) + 1
    return c
