# -*- coding: utf-8 -*-
"""حذف فایل‌های تکراری (بر اساس محتوا) از پوشه خروجی."""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")
    config = json.load(open(os.path.join(HERE, "config.json"), encoding="utf-8"))
    root = sys.argv[1] if len(sys.argv) > 1 else config["output_root"]
    dry = "--apply" not in sys.argv
    seen = {}
    removed = 0
    freed = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.startswith("_") or name.endswith(".csv") or name.endswith(".json"):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, "rb") as fh:
                    digest = hashlib.sha1(fh.read()).hexdigest()
            except OSError:
                continue
            if digest in seen:
                size = os.path.getsize(path)
                if dry:
                    print(f"[تکراری] {path}")
                else:
                    os.remove(path)
                removed += 1
                freed += size
            else:
                seen[digest] = path
    mode = "پیش‌نمایش" if dry else "حذف"
    print(f"{mode}: {removed} فایل تکراری، {freed / 1048576:.1f} مگابایت")
    if dry:
        print("برای حذف واقعی: python cleanup.py --apply")


if __name__ == "__main__":
    main()
