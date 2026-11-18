# -*- coding: utf-8 -*-
"""پاک‌سازی فایل‌های اشتباه‌ذخیره‌شده (HTML بدون پسوند) و اصلاح مانیفست."""
import io
import json
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
config = json.load(open(os.path.join(HERE, "config.json"), encoding="utf-8"))
root = config["output_root"]

removed = 0
for site in config["sites"]:
    site_dir = os.path.join(root, site["folder"])
    manifest_path = os.path.join(site_dir, "_manifest.json")
    if not os.path.exists(manifest_path):
        continue
    manifest = json.load(open(manifest_path, encoding="utf-8"))
    files_dir = os.path.join(site_dir, "فایل‌ها")
    bad_paths = set()
    if os.path.isdir(files_dir):
        for name in os.listdir(files_dir):
            path = os.path.join(files_dir, name)
            if not os.path.isfile(path) or os.path.splitext(name)[1]:
                continue
            with open(path, "rb") as fh:
                head = fh.read(200).lstrip().lower()
            if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
                os.remove(path)
                bad_paths.add(path)
                removed += 1
    if bad_paths:
        for key in list(manifest["downloaded"]):
            if manifest["downloaded"][key].get("path") in bad_paths:
                del manifest["downloaded"][key]
    trimmed = 0
    for entry in manifest["downloaded"].values():
        if "links" in entry:
            entry["link_count"] = len(entry.pop("links") or [])
            trimmed += 1
    json.dump(manifest, open(manifest_path, "w", encoding="utf-8"),
              ensure_ascii=False)
    if bad_paths:
        print(f"{site['folder']}: {len(bad_paths)} فایل HTML حذف و از مانیفست پاک شد")
    if trimmed:
        print(f"{site['folder']}: {trimmed} رکورد مانیفست سبک‌سازی شد")

print("مجموع حذف‌شده:", removed)
