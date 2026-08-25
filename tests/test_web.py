"""
Веб-интерфейс (этап 4): форма -> очередь -> подтверждение -> отчёт.

Проверяет требование к юзабилити из п. 2.6: отчёт получается целиком
через интерфейс, без консоли.
"""

import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from shadow_pki import cli, web

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "example-company.raw.json")


class Args:
    source = "crtsh"; token = ""; months = 24
    rules = cli.DEF_RULES; ownership = cli.DEF_OWNERSHIP
    also_own = []; review = False; save_raw = False
    no_dns = True; no_pdf = True          # PDF отдельно проверяется в test_pipeline
    fixture = FIXTURE; serve = 0


def get(base, path):
    return urllib.request.urlopen(base + path, timeout=20).read().decode()


def post(base, path, fields):
    data = urllib.parse.urlencode(fields).encode()
    try:
        return urllib.request.urlopen(urllib.request.Request(base + path, data=data), timeout=30)
    except urllib.error.HTTPError as ex:
        return ex          # 4xx — тоже ответ, а не сбой


def wait_for(base, job, marker, tries=120):
    for _ in range(tries):
        h = get(base, f"/job/{job}")
        if marker in h or "Не удалось" in h:
            return h
        time.sleep(0.25)
    return h


def run(check):
    web.JOBS.clear()
    with tempfile.TemporaryDirectory() as td:
        args = Args(); args.out = td
        srv, host = web.build_server(args, cli.load_yaml(args.rules),
                                     cli.load_yaml(args.ownership),
                                     host="127.0.0.1", port=0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            check("сервер отвечает", get(base, "/health"), "ok")
            check("форма отдаётся", "Построить отчёт" in get(base, "/"), True)

            bad = post(base, "/run", {"domain": "не домен", "source": "crtsh", "months": "24"})
            check("некорректный домен отклонён", bad.status, 400)
            check("задача при этом не создана", len(web.JOBS), 0)

            r = post(base, "/run", {"domain": "example.com", "also": "",
                                    "source": "crtsh", "months": "24"})
            job = r.url.rsplit("/", 1)[-1]
            check("задача создана", bool(job), True)

            h = wait_for(base, job, "ожидает подтверждения")
            check("дошло до экрана подтверждения", "ожидает подтверждения" in h, True)
            n = len(re.findall(r'name="d\d+"', h)) // 3
            check("на подтверждение вынесены только unknown", n, 1)

            post(base, f"/job/{job}/review", {"d0": "own"})
            h = wait_for(base, job, "готово")
            check("отчёт сформирован", "готово" in h, True)

            files = re.findall(r"/file/([^\"]+)\"", h)
            check("отчёт и экспорт доступны по ссылкам",
                  sorted(os.path.splitext(f)[1] for f in files),
                  [".csv", ".csv", ".html", ".json"])

            body = urllib.request.urlopen(
                base + f"/job/{job}/file/example.com.json", timeout=20).read()
            check("файл отдаётся", len(body) > 0, True)

            check("выход за каталог задачи закрыт", _forbidden(base, job), True)

            check("запуск попал в историю", job in get(base, "/"), True)
        finally:
            srv.shutdown()


def _forbidden(base, job):
    """Обход каталога должен упираться в 404, а не отдавать чужой файл."""
    try:
        urllib.request.urlopen(base + f"/job/{job}/file/..%2F..%2Findex.json", timeout=10)
        return False
    except urllib.error.HTTPError as ex:
        return ex.code == 404
    except Exception:
        return True
