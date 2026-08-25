#!/usr/bin/env python3
"""Запуск всех проверок: python3 tests/run.py"""
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODULES = ["test_lines", "test_no_host_contact", "test_pipeline"]


def main():
    failed = total = 0
    for name in MODULES:
        mod = __import__(f"tests.{name}", fromlist=["run"])
        print(f"\n{name}")
        results = []

        def check(label, got, want, _r=results):
            _r.append((label, got, want))

        try:
            mod.run(check)
        except Exception:
            print("  ОШИБКА при выполнении:")
            traceback.print_exc()
            failed += 1
            continue
        for label, got, want in results:
            total += 1
            ok = got == want
            failed += not ok
            print(f"  {'ok  ' if ok else 'FAIL'}  {label}"
                  + ("" if ok else f": {got!r}, ожидалось {want!r}"))
    print(f"\n{'—' * 46}")
    print(f"проверок: {total}, провалено: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
