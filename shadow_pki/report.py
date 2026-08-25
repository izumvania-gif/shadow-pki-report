"""
Отчёт (требования, п. 2.5).

HTML — основной путь, PDF печатается браузером. Плюс машиночитаемый
экспорт JSON и CSV.

Формулировки везде говорят о ФАКТЕ ВЫПУСКА, а не об использовании:
по реестрам неизвестно, работает ли сервис на имени и предъявляет ли он
именно этот сертификат.
"""

import csv
import html
import json
import os
import shutil
import subprocess
from collections import Counter

SEV_RU = {"critical": "Критично", "high": "Высокий", "medium": "Средний",
          "low": "Низкий", "info": "Информационно"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

CHROME_CANDIDATES = [
    os.environ.get("CHROME_PATH", ""),
    "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
    "/opt/pw-browsers/chromium/chrome-linux/chrome",
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
]

CSS = """
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body { font: 10.5pt/1.5 "PT Sans", "Segoe UI", Arial, sans-serif; color: #16191d; margin: 0; }
h1 { font-size: 21pt; margin: 0 0 4pt; letter-spacing: -.01em; }
h2 { font-size: 13pt; margin: 22pt 0 8pt; padding-bottom: 4pt; border-bottom: 1.5pt solid #16191d; }
h3 { font-size: 11pt; margin: 14pt 0 5pt; }
.sub { color: #5b636e; font-size: 10pt; margin-bottom: 16pt; }
.page { page-break-after: always; }
.page:last-child { page-break-after: auto; }
.cards { display: flex; flex-wrap: wrap; gap: 8pt; margin: 12pt 0 4pt; }
.card { flex: 1 1 118pt; border: 1pt solid #d6dae0; border-radius: 4pt; padding: 9pt 11pt; }
.card .n { font-size: 21pt; font-weight: 700; line-height: 1.1; }
.card .l { font-size: 8.5pt; color: #5b636e; text-transform: uppercase; letter-spacing: .04em; }
table { width: 100%; border-collapse: collapse; margin: 8pt 0; font-size: 9pt; }
th { text-align: left; background: #f2f4f6; padding: 5pt 6pt; border-bottom: 1pt solid #d6dae0;
     font-size: 8.5pt; text-transform: uppercase; letter-spacing: .03em; color: #414852; }
td { padding: 4.5pt 6pt; border-bottom: .75pt solid #e6e9ed; vertical-align: top; }
tr { page-break-inside: avoid; }
code, .mono { font-family: "DejaVu Sans Mono", Consolas, monospace; font-size: 8.5pt; }
.sev { display: inline-block; padding: 1pt 6pt; border-radius: 3pt; font-size: 8pt;
       font-weight: 700; text-transform: uppercase; letter-spacing: .03em; white-space: nowrap; }
.sev-critical { background: #b3261e; color: #fff; }
.sev-high     { background: #c9600c; color: #fff; }
.sev-medium   { background: #f0c419; color: #3d3000; }
.sev-low      { background: #e6e9ed; color: #414852; }
.finding { border-left: 2.5pt solid #d6dae0; padding: 2pt 0 2pt 10pt; margin: 10pt 0; page-break-inside: avoid; }
.finding.critical { border-left-color: #b3261e; }
.finding.high { border-left-color: #c9600c; }
.finding.medium { border-left-color: #f0c419; }
.finding .t { font-weight: 700; margin: 3pt 0 2pt; }
.finding .r { color: #414852; margin-top: 3pt; }
.finding .r b { color: #16191d; }
.note { background: #f2f4f6; border-radius: 4pt; padding: 10pt 12pt; margin: 10pt 0; font-size: 9.5pt; }
.note > b:first-child { display: block; margin-bottom: 3pt; }
ul { margin: 5pt 0; padding-left: 16pt; }
li { margin: 2.5pt 0; }
.muted { color: #5b636e; }
.yes { color: #1c6b3c; font-weight: 700; }
.no { color: #8a9099; }
footer { margin-top: 20pt; padding-top: 7pt; border-top: .75pt solid #d6dae0;
         font-size: 8.5pt; color: #5b636e; }
"""


def e(x):
    return html.escape(str(x if x is not None else "—"))


def plural(n, one, few, many):
    """Согласование числительного. Отчёт уходит заказчику, «1 линий» заметно."""
    n = abs(int(n or 0))
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} {one}"
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return f"{n} {few}"
    return f"{n} {many}"


def lines_n(n):
    return plural(n, "линия", "линии", "линий")


def lines_acc(n):
    return plural(n, "линию", "линии", "линий")


def names_n(n):
    return plural(n, "имя", "имени", "имён")


def ca_n(n):
    return plural(n, "удостоверяющий центр", "удостоверяющих центра", "удостоверяющих центров")


def _cards(s):
    items = [
        (s["certificate_lines"], "линий сертификатов"),
        (s["unique_names"], "имён"),
        (len(s["issuers_active"]), "УЦ действуют"),
        (s["findings_total"], "находок"),
    ]
    return "".join(
        f'<div class="card"><div class="n">{v}</div><div class="l">{e(l)}</div></div>'
        for v, l in items)


def render_html(ctx):
    s = ctx["summary"]
    by_sev = Counter(f["severity"] for f in ctx["findings"])

    sev_rows = "".join(
        f"<tr><td><span class='sev sev-{k}'>{SEV_RU[k]}</span></td>"
        f"<td class='mono'>{by_sev.get(k, 0)}</td></tr>"
        for k in SEV_ORDER if by_sev.get(k))

    obs = "".join(f"<li><b>{e(o['title'])}.</b> {e(o['text'])}</li>"
                  for o in ctx["observations"]) or "<li class='muted'>—</li>"

    findings = ""
    for sev in SEV_ORDER:
        group = [f for f in ctx["findings"] if f["severity"] == sev]
        if not group:
            continue
        findings += f"<h3><span class='sev sev-{sev}'>{SEV_RU[sev]}</span> &nbsp;{len(group)}</h3>"
        for f in group:
            findings += (
                f"<div class='finding {sev}'><div class='t'>{e(f['title'])}</div>"
                f"<div>{e(f['finding'])}</div>"
                f"<div class='r'><b>Рекомендация.</b> {e(f['recommendation'])}</div></div>")
    if not findings:
        findings = "<p class='muted'>Находок по действующему набору правил нет.</p>"

    name_rows = "".join(
        f"<tr><td class='mono'>{e(n['name'])}</td>"
        f"<td>{'<span class=yes>да</span>' if n['resolves'] else '<span class=no>нет</span>'}</td>"
        f"<td class='mono muted'>{e(', '.join(n['addresses'][:3]) or '—')}</td></tr>"
        for n in ctx["names"])

    cert_rows = "".join(
        f"<tr><td class='mono'>{e(l['names'][0])}"
        + (f"<div class='muted'>+{len(l['names']) - 1} имён в SAN</div>" if len(l["names"]) > 1 else "")
        + f"</td><td>{e((l['current'] or {}).get('issuer'))}</td>"
        f"<td class='mono'>{e(((l['current'] or {}).get('not_after') or '—')[:10])}</td>"
        f"<td class='mono'>{l['issuances']}</td>"
        f"<td class='mono'>{e(l['renewal_rhythm_days'] or '—')}</td></tr>"
        for l in ctx["lines"])

    skipped = ""
    if ctx["skipped_rules"]:
        skipped = ("<div class='note'><b>Правила, которые не применялись</b>"
                   "Источник не отдал полей, необходимых для этих проверок. "
                   "Отсутствие находок по ним не означает отсутствия проблем.<ul>"
                   + "".join(f"<li>{e(r['title'])} — {e(r['reason'])}</li>"
                             for r in ctx["skipped_rules"]) + "</ul></div>")

    withheld = ""
    if s["ownership"]["unknown"]:
        withheld = (f"<div class='note'><b>Записи, ожидающие подтверждения</b>"
                    f"{lines_acc(s['ownership']['unknown'])} не удалось однозначно отнести "
                    f"к компании или к внешнему владельцу. В находки они не включены.</div>")

    effort = ctx.get("effort_html") or (
        "<p class='muted'>Раздел не выводится: коэффициенты модели трудозатрат "
        "не подкреплены источником. См. <code>effort_model</code> в конфиге правил.</p>")

    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>Внешний аудит сертификатов — {e(s['domain'])}</title><style>{CSS}</style></head><body>

<div class="page">
<h1>Внешний аудит сертификатов</h1>
<div class="sub">{e(s['domain'])} · подготовлено {e(s['generated_at'][:10])} · горизонт выборки {e(s['horizon_months'])} мес.</div>
<div class="cards">{_cards(s)}</div>
<h2>Кратко</h2>
<p>По публичным реестрам на домен {e(s['domain'])} и его поддомены найдено
<b>{lines_n(s['certificate_lines'])}</b> сертификатов, покрывающих <b>{names_n(s['unique_names'])}</b>.
Действующие сертификаты выпущены через <b>{ca_n(len(s['issuers_active']))}</b>.
Актуальный сертификат истёк у <b>{lines_n(s['lines_current_expired'])}</b>,
в ближайшие 30 дней истекает <b>{lines_n(s['lines_expiring_30d'])}</b>.</p>
<table><tr><th>Уровень</th><th>Находок</th></tr>{sev_rows or "<tr><td colspan=2 class=muted>нет</td></tr>"}</table>
<h3>Наблюдения</h3><ul>{obs}</ul>
{withheld}
</div>

<div class="page">
<h2>Методология</h2>
<p>Отчёт построен <b>исключительно по публичным реестрам</b>: логам Certificate
Transparency и публичным DNS-записям. К инфраструктуре компании обращений не
производилось — соединения с хостами не устанавливались, TLS-хендшейк не
выполнялся, порты не сканировались. DNS-запросы уходили к публичным резолверам.</p>
<div class="note"><b>Что означают приведённые данные</b>
Реестры фиксируют <b>факт выпуска</b> сертификата, а не факт его использования.
Работает ли сервис на найденном имени и предъявляет ли он именно этот
сертификат — по публичным источникам неизвестно. Формулировки отчёта
построены соответственно.</div>
<div class="note"><b>Что в отчёт не попадает</b>
Самоподписанные сертификаты и сертификаты внутренних удостоверяющих центров
в Certificate Transparency не публикуются. Внутренний контур извне не
наблюдаем и в выборку не входит — приведённые цифры относятся только к
публично доверенным сертификатам внешнего периметра.</div>
<p class="muted">Единица счёта — <b>линия сертификата</b>: цепочка последовательных
выпусков на один набор имён. Автоматическое продление порождает десятки записей
в логе на одно имя; в отчёте они сведены в одну линию.
Обработано записей реестра: {s['raw_ct_records']}, из них схлопнуто
предсертификатов: {s['collapsed_precerts']}.</p>
{skipped}
</div>

<div class="page">
<h2>Находки</h2>
{findings}
</div>

<div class="page">
<h2>Имена</h2>
<table><tr><th>Имя</th><th>Резолвится</th><th>Адреса</th></tr>{name_rows}</table>
</div>

<div class="page">
<h2>Сертификаты</h2>
<table><tr><th>Имя</th><th>УЦ</th><th>Действует до</th><th>Выпусков</th><th>Ритм, дн.</th></tr>{cert_rows}</table>
</div>

<div>
<h2>Оценка объёма сопровождения</h2>
{effort}
<h2>Что остаётся за пределами этого отчёта</h2>
<p>Публичные реестры показывают меньшую часть картины. В выборку попало только
то, что выпущено публично доверенными УЦ и опубликовано в Certificate
Transparency. Сертификаты внутренних УЦ и самоподписанные в логи не
публикуются, поэтому внутренний контур извне не наблюдаем — а он, как
правило, существенно объёмнее внешнего периметра.</p>
<footer>Отчёт построен по публичным реестрам. Обращений к инфраструктуре
компании не производилось.</footer>
</div>

</body></html>"""


def find_chrome():
    for c in CHROME_CANDIDATES:
        if not c:
            continue
        p = shutil.which(c) if not os.path.isabs(c) else (c if os.path.exists(c) else None)
        if p:
            return p
    return None


def to_pdf(html_path, pdf_path):
    """Печать HTML в PDF браузером — основной путь по плану (этап 3)."""
    chrome = find_chrome()
    if not chrome:
        return None, "браузер не найден: задайте CHROME_PATH"
    cmd = [chrome, "--headless", "--disable-gpu", "--no-sandbox",
           "--no-pdf-header-footer", f"--print-to-pdf={pdf_path}",
           "file://" + os.path.abspath(html_path)]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=180)
    except (subprocess.TimeoutExpired, OSError) as ex:
        return None, f"{type(ex).__name__}: {ex}"
    if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
        return pdf_path, None
    return None, (r.stderr.decode("utf-8", "replace")[-400:] or "браузер не создал файл")


def write_exports(ctx, outdir, domain):
    """Машиночитаемый экспорт — задел под импорт в реестр Рутокен CLM."""
    os.makedirs(outdir, exist_ok=True)
    written = []

    jp = os.path.join(outdir, f"{domain}.json")
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(ctx, f, ensure_ascii=False, indent=2, default=str)
    written.append(jp)

    cp = os.path.join(outdir, f"{domain}.certificates.csv")
    with open(cp, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["имя", "все имена SAN", "УЦ", "действует до", "выпусков",
                    "ритм продления, дн.", "истёк", "wildcard", "принадлежность"])
        for l in ctx["lines"]:
            cur = l["current"] or {}
            w.writerow([l["names"][0], " ".join(l["names"]), cur.get("issuer", ""),
                        (cur.get("not_after") or "")[:10], l["issuances"],
                        l["renewal_rhythm_days"] or "", "да" if l["current_expired"] else "нет",
                        "да" if l["is_wildcard"] else "нет", l["ownership"]])
    written.append(cp)

    fp = os.path.join(outdir, f"{domain}.findings.csv")
    with open(fp, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["правило", "уровень", "заголовок", "объект", "находка", "рекомендация"])
        for x in ctx["findings"]:
            w.writerow([x["rule_id"], SEV_RU.get(x["severity"], x["severity"]),
                        x["title"], x["subject"], x["finding"], x["recommendation"]])
    written.append(fp)
    return written
