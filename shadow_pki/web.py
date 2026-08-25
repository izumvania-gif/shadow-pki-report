"""
Веб-интерфейс (этап 4).

Форма запуска, очередь задач, статус, экран ручного подтверждения,
история отчётов. Требование к юзабилити: продакт получает отчёт
самостоятельно, без обращения к разработчику и без консоли.

Авторизации нет — она отложена (требования, п. 2.6). Поэтому сервис
разворачивается ТОЛЬКО во внутренней сети: по умолчанию слушает
127.0.0.1. Открытый наружу инструмент без авторизации позволяет кому
угодно строить отчёты по любым доменам от нашего имени.

Зависимостей сверх PyYAML нет: http.server из стандартной библиотеки.
"""

import html
import json
import mimetypes
import os
import queue
import re
import threading
import traceback
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import pipeline
from .model import normalize_root
from .report import lines_n, plural

DOMAIN_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", re.I)
JOBS = {}
JOBS_LOCK = threading.Lock()
WORK = queue.Queue()
STATE = {"root": "out/jobs", "rules": {}, "own": {}, "args": None}


def e(x):
    return html.escape(str(x if x is not None else ""))


class Job:
    notice = None

    def __init__(self, jid, domain, opts):
        self.id = jid
        self.domain = domain
        self.opts = opts
        self.created = datetime.now(timezone.utc)
        self.status = "queued"
        self.error = None
        self.run = None
        self.files = []

    @property
    def outdir(self):
        return os.path.join(STATE["root"], self.id)

    def as_index(self):
        return {"id": self.id, "domain": self.domain,
                "created": self.created.isoformat(), "status": self.status,
                "files": [os.path.basename(f) for f in self.files],
                "findings": len(self.run.findings) if self.run else 0}


# --- очередь --------------------------------------------------------------

def worker():
    while True:
        jid, action = WORK.get()
        job = JOBS.get(jid)
        if not job:
            WORK.task_done()
            continue
        try:
            if action == "analyze":
                job.run = pipeline.Run(domain=job.domain, opts=job.opts,
                                       rules_cfg=STATE["rules"], own_cfg=STATE["own"])
                job.run.collect_phase()
                job.status = job.run.status
                job.run.resolve_phase()
                job.status = job.run.status
                job.run.mark_phase()
                job.status = job.run.status
                job.run.analyze_phase()
                if job.run.unknown_lines():
                    job.status = job.run.status = "awaiting_review"
                else:
                    WORK.put((jid, "render"))
                    job.status = "rendering"
            elif action == "render":
                job.status = "rendering"
                job.run.render_phase(job.outdir)
                job.files = job.run.written
                job.status = "done"
                save_index()
        except Exception as ex:
            job.status = "failed"
            job.error = f"{type(ex).__name__}: {ex}"
            traceback.print_exc()
            save_index()
        finally:
            WORK.task_done()


def save_index():
    os.makedirs(STATE["root"], exist_ok=True)
    with JOBS_LOCK:
        rows = [j.as_index() for j in JOBS.values()]
    rows.sort(key=lambda r: r["created"], reverse=True)
    with open(os.path.join(STATE["root"], "index.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)


def load_index():
    p = os.path.join(STATE["root"], "index.json")
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return json.load(f)


# --- разметка -------------------------------------------------------------

CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
       margin: 0; background: #f6f7f9; color: #16191d; }
main { max-width: 880px; margin: 0 auto; padding: 28px 20px 60px; }
h1 { font-size: 21px; margin: 0 0 2px; letter-spacing: -.01em; }
h2 { font-size: 15px; margin: 28px 0 10px; text-transform: uppercase;
     letter-spacing: .05em; color: #5b636e; }
.sub { color: #5b636e; font-size: 13px; margin-bottom: 22px; }
.card { background: #fff; border: 1px solid #e0e4e9; border-radius: 8px;
        padding: 18px 20px; margin-bottom: 14px; }
label { display: block; font-size: 13px; color: #414852; margin: 10px 0 4px; }
input[type=text], select { width: 100%; padding: 9px 11px; font-size: 15px;
        border: 1px solid #c8ced6; border-radius: 6px; background: #fff; color: inherit; }
.row { display: flex; gap: 12px; flex-wrap: wrap; }
.row > * { flex: 1 1 200px; }
button { font: inherit; font-weight: 600; padding: 10px 20px; border: 0;
         border-radius: 6px; background: #16191d; color: #fff; cursor: pointer; }
button.ghost { background: #eceff3; color: #16191d; }
button:hover { opacity: .88; }
a { color: #0b57a4; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th { text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: .04em;
     color: #5b636e; padding: 7px 8px; border-bottom: 1px solid #e0e4e9; font-weight: 600; }
td { padding: 9px 8px; border-bottom: 1px solid #eef0f3; vertical-align: top; }
.mono { font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 13px; }
.muted { color: #5b636e; }
.pill { display: inline-block; font-size: 12px; font-weight: 600; padding: 2px 9px;
        border-radius: 99px; white-space: nowrap; }
.p-done { background: #dcf0e3; color: #14562f; }
.p-failed { background: #fadcda; color: #8c1d16; }
.p-review { background: #fdefc8; color: #6b4e00; }
.p-run { background: #dde7f5; color: #123d70; }
.log { background: #f0f2f5; border-radius: 6px; padding: 11px 13px; font-size: 13px;
       margin-top: 12px; }
.log div { padding: 1px 0; color: #414852; }
.rev { border: 1px solid #e0e4e9; border-radius: 8px; padding: 12px 14px;
       margin-bottom: 9px; background: #fff; }
.rev .nm { font-family: ui-monospace, Consolas, monospace; font-size: 13.5px; word-break: break-all; }
.rev .meta { color: #5b636e; font-size: 13px; margin: 3px 0 9px; }
.choice { display: inline-flex; gap: 6px; align-items: center; margin-right: 16px;
          font-size: 14px; cursor: pointer; }
.bar { position: sticky; bottom: 0; background: #f6f7f9; border-top: 1px solid #e0e4e9;
       padding: 13px 0; margin-top: 16px; display: flex; gap: 10px; align-items: center; }
.warn { background: #fdefc8; border-radius: 6px; padding: 11px 13px; font-size: 13.5px;
        color: #6b4e00; margin-bottom: 14px; }
@media (prefers-color-scheme: dark) {
  body { background: #14171a; color: #e8eaed; }
  .card, .rev { background: #1d2124; border-color: #2f353a; }
  input[type=text], select { background: #14171a; border-color: #3a4147; color: #e8eaed; }
  button { background: #e8eaed; color: #14171a; } button.ghost { background: #2f353a; color: #e8eaed; }
  th { color: #9aa3ad; border-color: #2f353a; } td { border-color: #23282c; }
  .log { background: #23282c; } .log div { color: #b9c1c9; }
  .muted, .sub, h2 { color: #9aa3ad; } a { color: #7fb2f0; }
  .bar { background: #14171a; border-color: #2f353a; }
}
"""


def page(title, body):
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>"""


def pill(status):
    cls = {"done": "p-done", "failed": "p-failed",
           "awaiting_review": "p-review"}.get(status, "p-run")
    return f'<span class="pill {cls}">{e(pipeline.PHASE_RU.get(status, status))}</span>'


def index_page(msg=""):
    rows = ""
    for r in load_index():
        link = (f'<a href="/job/{e(r["id"])}">открыть</a>'
                if r["status"] in ("done", "awaiting_review") else "")
        rows += (f'<tr><td class="mono">{e(r["domain"])}</td>'
                 f'<td class="muted">{e(r["created"][:16].replace("T", " "))}</td>'
                 f'<td>{pill(r["status"])}</td>'
                 f'<td class="mono">{r["findings"] or ""}</td><td>{link}</td></tr>')
    history = (f'<table><tr><th>Домен</th><th>Запущен</th><th>Статус</th>'
               f'<th>Находок</th><th></th></tr>{rows}</table>'
               if rows else '<p class="muted">Запусков пока не было.</p>')

    return page("Shadow PKI Report", f"""
<h1>Внешний аудит сертификатов</h1>
<div class="sub">Отчёт по публичным реестрам. К инфраструктуре компании обращений не производится.</div>
{f'<div class="warn">{e(msg)}</div>' if msg else ''}
<form method="post" action="/run" class="card">
  <label for="domain">Корневой домен компании</label>
  <input type="text" id="domain" name="domain" placeholder="example.ru" required
         autofocus autocomplete="off" spellcheck="false">
  <label for="also">Дополнительные домены компании — через пробел, необязательно</label>
  <input type="text" id="also" name="also" autocomplete="off" spellcheck="false">
  <div class="row">
    <div><label for="source">Источник</label>
      <select id="source" name="source">
        <option value="crtsh">crt.sh</option>
        <option value="certspotter">Cert Spotter — с отпечатком ключа</option>
      </select></div>
    <div><label for="months">Горизонт выборки, мес.</label>
      <input type="text" id="months" name="months" value="24"></div>
  </div>
  <div style="margin-top:16px"><button type="submit">Построить отчёт</button></div>
</form>
<h2>История запусков</h2>
{history}""")


def job_page(job):
    if job.status == "failed":
        body = (f'<h1 class="mono">{e(job.domain)}</h1><div class="sub">{pill(job.status)}</div>'
                f'<div class="card"><b>Не удалось построить отчёт</b>'
                f'<div class="log"><div>{e(job.error)}</div></div></div>'
                f'<p><a href="/">← к запуску</a></p>')
        return page(f"Ошибка — {job.domain}", body)

    logs = "".join(f"<div>{e(m)}</div>" for m in (job.run.log if job.run else []))
    notes = notices(job)


    if job.status == "done":
        files = ""
        for f in job.files:
            n = os.path.basename(f)
            kind = {"pdf": "PDF-отчёт", "html": "HTML-версия", "json": "JSON-экспорт"}.get(
                n.rsplit(".", 1)[-1], "CSV-экспорт")
            files += (f'<tr><td>{e(kind)}</td>'
                      f'<td class="mono"><a href="/job/{e(job.id)}/file/{e(n)}">{e(n)}</a></td></tr>')
        s = job.run.summary()
        body = (f'<h1 class="mono">{e(job.domain)}</h1>'
                f'<div class="sub">{pill(job.status)} · найдено {lines_n(s["certificate_lines"])} '
                f'сертификатов, {plural(s["findings_total"], "находка", "находки", "находок")}</div>'
                f'{notes}'
                f'<div class="card"><table>{files}</table></div>'
                f'<div class="card"><b>Ход выполнения</b><div class="log">{logs}</div></div>'
                f'<p><a href="/">← новый запуск</a></p>')
        return page(f"Отчёт — {job.domain}", body)

    if job.status == "awaiting_review":
        return review_page(job)

    body = (f'<h1 class="mono">{e(job.domain)}</h1>'
            f'<div class="sub">{pill(job.status)}</div>'
            f'<div class="card"><div class="log">{logs or "<div>ожидание очереди…</div>"}</div></div>'
            f'<p class="muted">Страница обновляется автоматически.</p>')
    return page(f"Выполняется — {job.domain}", body).replace(
        "<head><meta charset=\"utf-8\">",
        "<head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"3\">")


def notices(job):
    out = ""
    if job.notice:
        out += f'<div class="warn">{e(job.notice)}</div>'
    for w in (job.run.warnings if job.run else []):
        out += f'<div class="warn">{e(w)}</div>'
    return out


def review_page(job):
    notes = notices(job)
    unknown = job.run.unknown_lines()
    items = ""
    for i, l in enumerate(unknown):
        cur = l.current
        names = ", ".join(l.names[:6]) + (f" (+{len(l.names) - 6})" if len(l.names) > 6 else "")
        items += f"""<div class="rev">
  <div class="nm">{e(names)}</div>
  <div class="meta">УЦ: {e(cur.issuer if cur else '—')} ·
    выпусков: {l.issuances} · действует до {e((cur.not_after.date() if cur and cur.not_after else '—'))}</div>
  <label class="choice"><input type="radio" name="d{i}" value="own"> наша</label>
  <label class="choice"><input type="radio" name="d{i}" value="foreign"> чужая</label>
  <label class="choice"><input type="radio" name="d{i}" value="" checked> пропустить</label>
</div>"""

    body = f"""<h1 class="mono">{e(job.domain)}</h1>
<div class="sub">{pill(job.status)} · {plural(len(unknown), 'запись', 'записи', 'записей')} не удалось разметить автоматически</div>
{notes}
<div class="warn">Отметьте, что принадлежит компании. Пропущенные записи в отчёт не попадут.
Решения сохраняются и используются для автоматизации фильтра.</div>
<form method="post" action="/job/{e(job.id)}/review">
{items}
<div class="bar">
  <button type="submit">Сформировать отчёт</button>
  <button type="button" class="ghost" onclick="pick('own')">все наши</button>
  <button type="button" class="ghost" onclick="pick('foreign')">все чужие</button>
  <span class="muted">пропущенные записи будут исключены</span>
</div></form>
<script>function pick(v){{document.querySelectorAll('input[type=radio][value="'+v+'"]')
.forEach(function(r){{r.checked=true}})}}</script>"""
    return page(f"Подтверждение — {job.domain}", body)


# --- HTTP -----------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "shadow-pki-report"

    def log_message(self, fmt, *a):
        # Аудит: кто инициировал — не пишем, авторизации нет (п. 2.7).
        print(f"[web] {self.address_string()} {fmt % a}")

    def _send(self, body, code=200, ctype="text/html; charset=utf-8", extra=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, to):
        self.send_response(303)
        self.send_header("Location", to)
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            return self._send(index_page())
        if path == "/health":
            return self._send("ok", ctype="text/plain; charset=utf-8")

        m = re.match(r"^/job/([a-z0-9]+)(/file/(.+))?$", path)
        if m:
            job = JOBS.get(m.group(1))
            if not job:
                return self._send(page("Не найдено", "<h1>Задача не найдена</h1>"
                                       "<p><a href='/'>← к запуску</a></p>"), 404)
            if m.group(3):
                name = os.path.basename(urllib.parse.unquote(m.group(3)))
                fp = os.path.join(job.outdir, name)
                if not os.path.exists(fp):
                    return self._send("нет файла", 404, "text/plain; charset=utf-8")
                ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
                if name.endswith(".csv"):
                    ctype = "text/csv; charset=utf-8"
                with open(fp, "rb") as f:
                    return self._send(f.read(), ctype=ctype)
            return self._send(job_page(job))
        return self._send(page("Не найдено", "<h1>404</h1>"), 404)

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            return {}
        raw = self.rfile.read(n).decode("utf-8", "replace")
        return urllib.parse.parse_qs(raw, keep_blank_values=True)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/run":
            f = self._form()
            domain, stripped = normalize_root(f.get("domain", [""])[0])
            if not DOMAIN_RE.match(domain):
                return self._send(index_page("Домен указан неверно. Пример: example.ru"), 400)
            also = [d.strip().lower() for d in (f.get("also", [""])[0] or "").split()
                    if DOMAIN_RE.match(d.strip().lower())]
            try:
                months = max(0, min(120, int((f.get("months", ["24"])[0] or "24").strip())))
            except ValueError:
                months = 24
            source = f.get("source", ["crtsh"])[0]
            source = source if source in ("crtsh", "certspotter") else "crtsh"

            jid = f"{int(datetime.now(timezone.utc).timestamp())}{len(JOBS):02d}"
            args = STATE["args"]
            opts = pipeline.Options(source=source, token=getattr(args, "token", ""),
                                    months=months, also_own=tuple(also),
                                    no_dns=getattr(args, "no_dns", False),
                                    no_pdf=getattr(args, "no_pdf", False),
                                    fixture=getattr(args, "fixture", None))
            job = Job(jid, domain, opts)
            if stripped:
                job.notice = ("Введён домен с префиксом www — отчёт построен "
                              f"по корневому домену {domain}.")
            with JOBS_LOCK:
                JOBS[jid] = job
            save_index()
            WORK.put((jid, "analyze"))
            return self._redirect(f"/job/{jid}")

        m = re.match(r"^/job/([a-z0-9]+)/review$", path)
        if m:
            job = JOBS.get(m.group(1))
            if not job or job.status != "awaiting_review":
                return self._redirect("/")
            f = self._form()
            decisions = {}
            for k, v in f.items():
                if k.startswith("d") and k[1:].isdigit() and v and v[0] in ("own", "foreign"):
                    decisions[int(k[1:])] = v[0]
            job.run.apply_decisions(decisions)
            job.status = "rendering"
            WORK.put((job.id, "render"))
            return self._redirect(f"/job/{job.id}")

        return self._send("нет такого маршрута", 404, "text/plain; charset=utf-8")


def build_server(args, rules_cfg, own_cfg, host=None, port=None):
    """Собирает сервер и поднимает воркер. Отдельно от serve() ради тестов."""
    STATE["rules"] = rules_cfg
    STATE["own"] = own_cfg
    STATE["args"] = args
    STATE["root"] = os.path.join(args.out, "jobs")
    os.makedirs(STATE["root"], exist_ok=True)

    threading.Thread(target=worker, daemon=True).start()

    host = host or os.environ.get("SHADOW_PKI_HOST", "127.0.0.1")
    port = args.serve if port is None else port
    return ThreadingHTTPServer((host, port), Handler), host


def serve(args, rules_cfg, own_cfg, host=None, port=None):
    srv, host = build_server(args, rules_cfg, own_cfg, host, port)
    port = srv.server_address[1]
    print(f"Веб-интерфейс: http://{host}:{port}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("ВНИМАНИЕ: авторизации нет. Публиковать наружу нельзя — "
              "инструмент рассчитан на внутреннюю сеть.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nостановлено")
    return 0
