"""
Пайплайн по фазам.

Разбит на фазы, потому что перед формированием финального отчёта нужна
пауза на ручное подтверждение (требования, п. 2.3): оператор разбирает
категорию unknown. CLI и веб-интерфейс используют одни и те же фазы.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import collect, ownership as own_mod, report, rules as rules_mod

PHASES = ["queued", "collecting", "resolving", "marking", "analyzing",
          "awaiting_review", "rendering", "done", "failed"]

PHASE_RU = {
    "queued": "в очереди",
    "collecting": "выгрузка из Certificate Transparency",
    "resolving": "запрос публичных DNS-записей",
    "marking": "разметка принадлежности",
    "analyzing": "применение правил",
    "awaiting_review": "ожидает подтверждения",
    "rendering": "формирование отчёта",
    "done": "готово",
    "failed": "ошибка",
}


@dataclass
class Options:
    source: str = "crtsh"
    token: str = ""
    months: int = 24
    also_own: tuple = ()
    no_dns: bool = False
    no_pdf: bool = False
    fixture: str = None
    save_raw: bool = False
    out: str = "out"


@dataclass
class Run:
    domain: str
    opts: Options
    rules_cfg: dict
    own_cfg: dict
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    status: str = "queued"
    error: str = None
    log: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    certs: list = field(default_factory=list)
    collapsed: int = 0
    lines: list = field(default_factory=list)
    names_info: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    observations: list = field(default_factory=list)
    active_issuers: object = None
    written: list = field(default_factory=list)

    def note(self, msg):
        self.log.append(msg)
        return msg

    def warn(self, msg):
        """Предупреждение попадает и в лог, и в методологию отчёта."""
        if msg not in self.warnings:
            self.warnings.append(msg)
        self.log.append("ВНИМАНИЕ: " + msg)
        return msg

    # --- фазы ---------------------------------------------------------

    def collect_phase(self):
        self.status = "collecting"
        if self.opts.fixture:
            with open(self.opts.fixture, encoding="utf-8") as f:
                raw = json.load(f)
            self.note(f"фикстура: {self.opts.fixture}")
        else:
            raw = collect.fetch_raw(self.domain, self.opts.source, self.opts.token)
            if self.opts.save_raw:
                os.makedirs(self.opts.out, exist_ok=True)
                p = os.path.join(self.opts.out, f"{self.domain}.raw.json")
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(raw, f, ensure_ascii=False)
                self.note(f"сырая выгрузка сохранена: {p}")

        certs = collect.normalize(raw, "crtsh" if self.opts.fixture else self.opts.source)
        self.note(f"записей реестра: {len(certs)}")

        if self.opts.months:
            cut = self.now - timedelta(days=30 * self.opts.months)
            certs = [c for c in certs if (c.not_before or self.now) >= cut]
            self.note(f"в горизонте {self.opts.months} мес.: {len(certs)}")

        self.certs, self.collapsed = collect.dedup_precerts(certs)
        self.lines = collect.build_lines(self.certs)
        self.note(f"линий сертификатов: {len(self.lines)} "
                  f"(схлопнуто предсертификатов: {self.collapsed})")
        self.check_plausibility()
        return self

    def check_plausibility(self):
        """
        Неполный ответ источника выглядит как маленькая компания.

        Молча принятая усечённая выгрузка опаснее ошибки: отчёт занижает
        картину, и это не видно ни составителю, ни заказчику.
        """
        n = len(self.certs)
        if n and not self.collapsed:
            self.warn("предсертификаты в выборке не найдены — обычно каждый "
                      "сертификат публикуется вместе с предсертификатом. "
                      "Похоже на неполный ответ источника, стоит повторить прогон")
        if 0 < n < 10:
            self.warn(f"получено всего {n} записей реестра. Для домена компании "
                      "это неправдоподобно мало: проверьте, что указан корневой "
                      "домен, и повторите прогон")
        if not n:
            self.warn("источник не вернул ни одной записи по этому домену")

    def resolve_phase(self):
        self.status = "resolving"
        names = sorted({n for l in self.lines for n in l.names})
        if self.opts.no_dns:
            self.names_info = {n: collect.NameInfo(name=n, checked=False) for n in names}
            self.note("DNS пропущен")
        else:
            self.names_info = collect.resolve_names(names)
            ok = sum(1 for i in self.names_info.values() if i.resolves)
            self.note(f"резолвится {ok} из {len(names)} имён")
        return self

    def mark_phase(self):
        self.status = "marking"
        self.owner = own_mod.Ownership(
            self.own_cfg, root_domains=[self.domain] + list(self.opts.also_own))
        self.owner.apply(self.lines, self.names_info)
        c = own_mod.counts(self.lines)
        self.note(f"принадлежность: наши {c['own']}, чужие {c['foreign']}, "
                  f"требуют подтверждения {c['unknown']}")
        return self

    def analyze_phase(self):
        self.status = "analyzing"
        self.findings, self.skipped = rules_mod.run(
            self.rules_cfg, self.lines, self.names_info, self.now)
        self.observations, self.active_issuers = rules_mod.observations(
            self.rules_cfg, self.lines, self.now)
        self.note(f"находок: {len(self.findings)}"
                  + (f", правил не применялось: {len(self.skipped)}" if self.skipped else ""))
        return self

    # --- ручное подтверждение ------------------------------------------

    def unknown_lines(self):
        return [l for l in self.lines if l.ownership == "unknown"]

    def apply_decisions(self, decisions):
        """decisions: {индекс в unknown_lines -> 'own' | 'foreign'}"""
        unknown = self.unknown_lines()
        recorded = []
        for idx, verdict in decisions.items():
            if not (0 <= idx < len(unknown)) or verdict not in ("own", "foreign"):
                continue
            l = unknown[idx]
            l.ownership = verdict
            l.ownership_reason = ("подтверждено оператором" if verdict == "own"
                                  else "отклонено оператором")
            recorded.append((l.names, verdict))
        if recorded:
            p = self.owner.record_decisions(recorded, self.domain)
            if p:
                self.note(f"решений оператора записано: {len(recorded)} -> {p}")
        # правила пересчитываются: состав наших записей изменился
        self.analyze_phase()
        return len(recorded)

    # --- результат ------------------------------------------------------

    def summary(self):
        scored = [l for l in self.lines if l.ownership == "own"]
        return {
            "domain": self.domain,
            "generated_at": self.now.isoformat(),
            "horizon_months": self.opts.months,
            "source": "fixture" if self.opts.fixture else self.opts.source,
            "raw_ct_records": len(self.certs) + self.collapsed,
            "collapsed_precerts": self.collapsed,
            "certificate_lines": len(scored),
            "unique_names": len({n for l in scored for n in l.names}),
            "wildcard_lines": sum(1 for l in scored if l.is_wildcard),
            "lines_current_expired": sum(1 for l in scored if l.current_expired(self.now)),
            "lines_expiring_30d": sum(
                1 for l in scored if not l.current_expired(self.now)
                and l.days_to_expiry(self.now) is not None
                and l.days_to_expiry(self.now) <= 30),
            "issuers_active": (self.active_issuers or {}) and self.active_issuers.most_common(),
            "ownership": own_mod.counts(self.lines),
            "findings_total": len(self.findings),
        }

    def context(self):
        scored = [l for l in self.lines if l.ownership == "own"]
        names = sorted({n for l in scored for n in l.names})
        ctx = {
            "summary": self.summary(),
            "findings": [f.as_dict() for f in self.findings],
            "skipped_rules": self.skipped,
            "warnings": list(self.warnings),
            "observations": self.observations,
            "lines": [l.as_dict(self.now) for l in scored],
            "names": [self.names_info[n].as_dict() for n in names if n in self.names_info],
            "excluded": [{"names": list(l.names), "level": l.ownership,
                          "reason": l.ownership_reason}
                         for l in self.lines if l.ownership != "own"],
        }
        ctx["effort_html"] = effort_html(self.rules_cfg, len(scored))
        return ctx

    def render_phase(self, outdir=None):
        self.status = "rendering"
        outdir = outdir or self.opts.out
        os.makedirs(outdir, exist_ok=True)
        ctx = self.context()

        hp = os.path.join(outdir, f"{self.domain}.html")
        with open(hp, "w", encoding="utf-8") as f:
            f.write(report.render_html(ctx))
        self.written = [hp] + report.write_exports(ctx, outdir, self.domain)

        if not self.opts.no_pdf:
            pdf, err = report.to_pdf(hp, os.path.join(outdir, f"{self.domain}.pdf"))
            if pdf:
                self.written.append(pdf)
            else:
                self.note(f"PDF не создан ({err}); HTML готов, печать из браузера")
        self.status = "done"
        return self


def effort_html(cfg, lines_count):
    """Раздел о трудозатратах без источника коэффициентов не выводится."""
    m = (cfg or {}).get("effort_model") or {}
    ratio = m.get("internal_to_external_ratio") or {}
    hours = m.get("hours_per_manual_renewal") or {}
    if not (ratio.get("value") and ratio.get("source")
            and hours.get("value") and hours.get("source")):
        return None
    total = lines_count * ratio["value"]
    per_year = total * (365 / 47)
    return (f"<p>Найдено {lines_count} линий на внешнем периметре. "
            f"При соотношении внутренних и внешних сертификатов 1:{ratio['value']} "
            f"это ориентировочно {int(total)} сертификатов. При текущем сроке жизни — "
            f"около {int(per_year)} операций продления в год, "
            f"или {int(per_year * hours['value'])} человеко-часов.</p>"
            f"<p class='muted'>Источники: {ratio['source']}; {hours['source']}.</p>")
