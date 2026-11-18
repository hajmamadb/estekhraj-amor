# -*- coding: utf-8 -*-
"""ساخت متادیتا برای فایل‌هایی که پیش از افزودن سامانه متادیتا دانلود شده‌اند."""
import hashlib
import io
import json
import os
import sys
import urllib.parse

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
config = json.load(open(os.path.join(HERE, "config.json"), encoding="utf-8"))
root = config.get("output_root") or "."
root = root if os.path.isabs(root) else os.path.abspath(os.path.join(HERE, root))

meta_path = os.path.join(root, "metadata.jsonl")
existing = set()
if os.path.exists(meta_path):
    with open(meta_path, encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            existing.add(rec.get("id"))

added = 0
with open(meta_path, "a", encoding="utf-8") as out:
    for site in config["sites"]:
        site_dir = os.path.join(root, site["folder"])
        manifest_path = os.path.join(site_dir, "_manifest.json")
        if not os.path.exists(manifest_path):
            continue
        manifest = json.load(open(manifest_path, encoding="utf-8"))
        changed = False
        for entry in manifest.get("downloaded", {}).values():
            path = entry.get("path")
            if not path or os.path.exists(path):
                continue
            marker = os.sep + site["folder"] + os.sep
            if marker in path:
                tail = path.split(marker, 1)[1]
                entry["path"] = os.path.join(site_dir, tail)
                changed = True
        if changed:
            json.dump(manifest, open(manifest_path, "w", encoding="utf-8"),
                      ensure_ascii=False)
        for key, entry in manifest.get("downloaded", {}).items():
            path = entry.get("path")
            if not path or not os.path.exists(path):
                continue
            if key in existing:
                continue
            size = os.path.getsize(path)
            with open(path, "rb") as fh:
                digest = hashlib.sha1(fh.read()).hexdigest()
            rec = {
                "id": key,
                "type": entry.get("type", "file"),
                "source_site": site["name"],
                "source_site_url": site.get("start_urls", [""])[0],
                "source_domain": urllib.parse.urlsplit(
                    entry.get("url", "")).hostname or "",
                "source_page": entry.get("referrer") or "",
                "source_url": entry.get("url", ""),
                "final_url": entry.get("url", ""),
                "title": entry.get("title") or os.path.basename(path),
                "file_name": os.path.basename(path),
                "local_path": os.path.relpath(path, root),
                "content_type": "",
                "size_bytes": size,
                "sha1": digest,
                "depth": 0,
                "backfilled": True,
            }
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            added += 1

print(f"{added} رکورد متادیتا برای فایل‌های قبلی ساخته شد")
