"""
Ключевое требование продукта (НФТ, п. 2.7): сервис не устанавливает
соединений с хостами компании, по которой строится отчёт.

Тест перехватывает исходящие TCP-соединения и прогоняет полный пайплайн,
включая DNS-резолвинг. Любое соединение к найденному имени — провал.
Требование не должно держаться на договорённости.
"""

import os
import socket
import sys
import tempfile

from shadow_pki import cli, collect

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "example-company.raw.json")


class Args:
    source = "crtsh"
    token = ""
    months = 24
    rules = cli.DEF_RULES
    ownership = cli.DEF_OWNERSHIP
    also_own = []
    review = False
    save_raw = False
    no_dns = False       # DNS включён намеренно: он тоже под наблюдением
    no_pdf = True
    fixture = FIXTURE


def run(check):
    connected = []
    real_connect = socket.socket.connect
    real_conn_ex = socket.socket.connect_ex
    real_create = socket.create_connection

    def spy(self, addr, *a, **kw):
        connected.append(addr[0] if isinstance(addr, tuple) else str(addr))
        return real_connect(self, addr, *a, **kw)

    def spy_ex(self, addr, *a, **kw):
        connected.append(addr[0] if isinstance(addr, tuple) else str(addr))
        return real_conn_ex(self, addr, *a, **kw)

    def spy_create(addr, *a, **kw):
        connected.append(addr[0] if isinstance(addr, tuple) else str(addr))
        return real_create(addr, *a, **kw)

    socket.socket.connect = spy
    socket.socket.connect_ex = spy_ex
    socket.create_connection = spy_create
    try:
        with tempfile.TemporaryDirectory() as td:
            args = Args()
            args.out = td
            from datetime import datetime, timezone
            summary = cli.process("example.com", args,
                                  cli.load_yaml(args.rules),
                                  cli.load_yaml(args.ownership),
                                  datetime.now(timezone.utc))
            import json
            with open(os.path.join(td, "example.com.json"), encoding="utf-8") as f:
                ctx = json.load(f)
    finally:
        socket.socket.connect = real_connect
        socket.socket.connect_ex = real_conn_ex
        socket.create_connection = real_create

    found = {n["name"] for n in ctx["names"]}
    found |= {n for l in ctx["lines"] for n in l["names"]}
    addrs = {a for n in ctx["names"] for a in n["addresses"]}

    hit_names = sorted(set(connected) & found)
    hit_addrs = sorted(set(connected) & addrs)

    check("соединений с найденными именами нет", hit_names, [])
    check("соединений с адресами найденных имён нет", hit_addrs, [])

    outside = [h for h in set(connected)
               if not any(h.endswith(a) for a in collect.ALLOWED_HOSTS)]
    check("соединения только к разрешённым источникам", outside, [])
    check("пайплайн отработал", summary["certificate_lines"] > 0, True)
