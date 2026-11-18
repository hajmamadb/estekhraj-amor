# -*- coding: utf-8 -*-
"""
جمع‌آوری کامل محتوای سایت‌های آماری ایران

قابلیت‌ها:
  * کشف خودکار تمام لینک‌های داخلی (بدون فهرست دستی)
  * خواندن sitemap.xml / sitemap_index.xml / robots.txt
  * دانلود فایل‌ها (PDF, Excel, Word, ZIP, ...) و ذخیره HTML + متن هر صفحه
  * استخراج جدول‌های صفحه به CSV و داده‌های JSON جاسازی‌شده
  * ادامه از نقطه قطع (resume) با مانیفست مستقل هر سایت
  * ساخت خودکار config.discovered.json از نتایج خزش

اجرا:
    python harvester.py                      همه سایت‌ها
    python harvester.py --site ایمیدرو        فقط یک سایت
    python harvester.py --limit 20           سقف صفحات هر سایت (آزمایشی)
    python harvester.py --parallel 3         سه سایت هم‌زمان
"""
import argparse
import csv
import hashlib
import html as html_mod
import html.parser
import io
import json
import os
import re
import ssl
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

DOC_EXTENSIONS = {
    ".pdf", ".xls", ".xlsx", ".xlsm", ".xlsb", ".csv", ".doc", ".docx",
    ".ppt", ".pptx", ".zip", ".rar", ".7z", ".txt", ".json", ".xml", ".mdb",
    ".accdb", ".dbf", ".sav", ".dta", ".ashx", ".dat", ".ods", ".odt",
}
SKIP_EXTENSIONS = {
    ".css", ".js", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".svg",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".mp4", ".mp3",
    ".avi", ".mov", ".map", ".swf",
}
TRACKING_PARAMS = {"cdv", "ver", "v", "_", "utm_source", "utm_medium",
                   "utm_campaign", "utm_term", "utm_content", "gclid",
                   "fbclid", "yclid", "mc_cid", "mc_eid"}
DOC_HINTS = ("getfile", "/file/", "download", "file_id=", "attachment",
             "dl.php", "/uploads/", "/portals/0/")

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

PRINT_LOCK = threading.Lock()


def log(msg):
    stamp = datetime.now().strftime("%H:%M:%S")
    with PRINT_LOCK:
        print(f"[{stamp}] {msg}", flush=True)


def sanitize_name(name, max_len=110):
    name = urllib.parse.unquote(str(name))
    name = name.replace("+", " ")
    name = unicodedata.normalize("NFC", name)
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    name = re.sub(r"\s+", " ", name).strip(" ._")
    if not name:
        name = "بدون-نام"
    if len(name) > max_len:
        root, ext = os.path.splitext(name)
        name = root[: max_len - len(ext)] + ext
    return name


def url_hash(url):
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]


def quote_url(url):
    parts = urllib.parse.urlsplit(url)
    path = urllib.parse.quote(parts.path, safe="/%:@&=+$,;~()'-._!*")
    query = urllib.parse.quote(parts.query, safe="=&%:@+,;~()'-._!*/?")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, ""))


def decode_html(data):
    for enc in ("utf-8", "windows-1256", "cp1256", "iso-8859-6", "cp1252"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def sniff_ext(data):
    """پسوند فایل را از امضای بایتی تشخیص می‌دهد."""
    head = data[:8]
    if head.startswith(b"%PDF"):
        return ".pdf"
    if head.startswith(b"PK\x03\x04"):
        if b"word/" in data[:2000]:
            return ".docx"
        if b"xl/" in data[:2000]:
            return ".xlsx"
        if b"ppt/" in data[:2000]:
            return ".pptx"
        return ".zip"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return ".xls"
    if head.startswith(b"Rar!"):
        return ".rar"
    if head.startswith(b"7z\xbc\xaf"):
        return ".7z"
    if head[:5] in (b"<?xml", b"<htm"):
        return ".xml" if head.startswith(b"<?xml") else ".html"
    return ""


def normalize_url(base, href):
    href = html_mod.unescape(str(href).strip())
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:",
                                    "data:", "whatsapp:", "sms:")):
        return None
    try:
        absolute = urllib.parse.urljoin(base, href)
    except ValueError:
        return None
    parts = urllib.parse.urlsplit(absolute)
    if parts.scheme not in ("http", "https"):
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    netloc = host
    if parts.port and parts.port not in (80, 443):
        netloc = f"{host}:{parts.port}"
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    pairs = [(k, v) for k, v in pairs if k.lower() not in TRACKING_PARAMS]
    query = urllib.parse.urlencode(pairs, doseq=True)
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return urllib.parse.urlunsplit((parts.scheme, netloc, path, query, ""))


def upgrade_scheme(url, hosts):
    """برای دامنه‌های هدف، http را به https ارتقا می‌دهد."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "http" and (parts.hostname or "").lower() in hosts:
        return urllib.parse.urlunsplit(("https", parts.netloc, parts.path,
                                        parts.query, ""))
    return url


class PageParser(html.parser.HTMLParser):
    """استخراج لینک، عنوان، متن، جدول و JSON جاسازی‌شده از یک صفحه."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.title = ""
        self.text_parts = []
        self.tables = []
        self.json_blobs = []
        self._in_title = False
        self._skip = 0
        self._table = None
        self._row = None
        self._cell = None
        self._script_buf = None
        self._script_type = ""

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag in ("iframe", "frame", "embed") and attrs.get("src"):
            self.links.append(attrs["src"])
        elif tag == "form" and attrs.get("action"):
            self.links.append(attrs["action"])
        elif tag == "title":
            self._in_title = True
        elif tag in ("script", "style"):
            self._skip += 1
            if tag == "script":
                self._script_buf = []
                self._script_type = attrs.get("type", "").lower()
        elif tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style"):
            if self._skip:
                self._skip -= 1
            if tag == "script" and self._script_buf is not None:
                self._collect_script()
                self._script_buf = None
        elif tag in ("td", "th") and self._cell is not None:
            if self._row is not None:
                self._row.append(" ".join(x.strip() for x in self._cell if x.strip()))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if self._table is not None and any(c for c in self._row):
                self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            if len(self._table) >= 2:
                self.tables.append(self._table)
            self._table = None

    def handle_data(self, data):
        if self._script_buf is not None:
            self._script_buf.append(data)
            return
        if self._in_title:
            self.title += data
            return
        if self._skip:
            return
        if self._cell is not None:
            self._cell.append(data)
            return
        data = data.strip()
        if data:
            self.text_parts.append(data)

    def _collect_script(self):
        buf = "".join(self._script_buf).strip()
        if len(buf) < 200:
            return
        if "json" not in self._script_type:
            match = re.search(r"=\s*(\{.*\}|\[.*\])\s*;?\s*$", buf, re.S)
            if not match:
                return
            buf = match.group(1)
        try:
            json.loads(buf)
        except Exception:
            return
        if len(self.json_blobs) < 30:
            self.json_blobs.append(buf)

    @property
    def text(self):
        return "\n".join(self.text_parts)


class SiteCrawler:
    def __init__(self, harvester, site):
        self.h = harvester
        self.site = site
        self.name = site["name"]
        self.folder = site["folder"]
        self.dir = os.path.join(harvester.root, self.folder)
        self.allowed_hosts = {h.lower() for h in site.get("allowed_hosts", [])}
        self.max_depth = site.get("max_depth", 6)
        site_max = site.get("max_pages") or harvester.default_max_pages
        self.max_pages = min(site_max, harvester.limit_override) \
            if harvester.limit_override else site_max
        self.delay = site.get("delay", harvester.default_delay)
        self.exclude = [re.compile(p) for p in site.get("exclude_patterns", [])]
        self.include = [re.compile(p) for p in site.get("include_patterns", [])]
        self.extract_tables = site.get("extract_tables", True)
        self.use_sitemap = site.get("sitemap", True)
        self.manifest_path = os.path.join(self.dir, "_manifest.json")
        self.manifest = self._load()
        self.seen = set()
        self.discovered = []
        self.stats = {"pages": 0, "files": 0, "bytes": 0, "errors": 0}
        self.robots = None
        self.sitemaps_from_robots = []
        self._last_request = 0.0
        self.consecutive_failures = 0
        self.aborted = False

    def _load(self):
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, encoding="utf-8") as fh:
                    data = json.load(fh)
                data.setdefault("downloaded", {})
                data.setdefault("failed", {})
                return data
            except Exception:
                pass
        return {"downloaded": {}, "failed": {}}

    def save_manifest(self):
        os.makedirs(self.dir, exist_ok=True)
        tmp = self.manifest_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.manifest, fh, ensure_ascii=False)
        os.replace(tmp, self.manifest_path)

    def _throttle(self):
        if self.delay <= 0:
            return
        wait = self.delay - (time.time() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.time()

    def open_url(self, url):
        url = upgrade_scheme(url, self.allowed_hosts)
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fa-IR,fa;q=0.9,en;q=0.7",
        }
        last = None
        for attempt in range(1, self.h.retries + 1):
            self._throttle()
            try:
                req = urllib.request.Request(quote_url(url), headers=headers)
                resp = urllib.request.urlopen(req, timeout=self.h.timeout,
                                              context=SSL_CTX)
                self.consecutive_failures = 0
                return resp
            except urllib.error.HTTPError as exc:
                last = exc
                if exc.code in (400, 401, 403, 404, 410) and attempt >= 2:
                    break
                time.sleep(min(2 * attempt, 8))
            except Exception as exc:
                last = exc
                if isinstance(exc, (TimeoutError, OSError)) and attempt >= 2:
                    time.sleep(1)
                    break
                time.sleep(min(2 * attempt, 8))
        raise last

    def fetch(self, url):
        resp = self.open_url(url)
        ctype = (resp.headers.get("Content-Type") or "").lower()
        chunks = []
        total = 0
        while True:
            chunk = resp.read(1 << 18)
            if not chunk:
                break
            total += len(chunk)
            if total > self.h.max_file_bytes:
                raise ValueError("حجم فایل از سقف مجاز بیشتر است")
            chunks.append(chunk)
        return b"".join(chunks), ctype, resp.geturl(), resp.headers

    def load_robots(self):
        hosts = sorted(self.allowed_hosts)
        if not hosts:
            return
        rules = []
        for host in hosts[:1]:
            for scheme in ("https", "http"):
                try:
                    data, _ctype, _final, _hdr = self.fetch(f"{scheme}://{host}/robots.txt")
                except Exception:
                    continue
                text = data.decode("utf-8", "replace")
                current = None
                for line in text.splitlines():
                    line = line.split("#")[0].strip()
                    if not line or ":" not in line:
                        continue
                    key, val = line.split(":", 1)
                    key, val = key.strip().lower(), val.strip()
                    if key == "user-agent":
                        current = val
                    elif key == "disallow" and current == "*" and val:
                        rules.append(val)
                    elif key == "sitemap" and val:
                        self.sitemaps_from_robots.append(val)
                break
        self.robots = rules

    def robots_allows(self, url):
        if not self.robots:
            return True
        path = urllib.parse.urlsplit(url).path or "/"
        for rule in self.robots:
            if rule == "/":
                return False
            clean = rule.replace("*", "")
            if clean and path.startswith(clean):
                return False
        return True

    def sitemap_urls(self, limit=20000):
        candidates = list(self.site.get("sitemap_urls", [])) + self.sitemaps_from_robots
        for host in sorted(self.allowed_hosts)[:1]:
            candidates += [
                f"https://{host}/sitemap.xml",
                f"https://{host}/sitemap_index.xml",
                f"https://{host}/wp-sitemap.xml",
                f"https://{host}/sitemap-index.xml",
            ]
        found, visited = [], set()
        queue = deque(candidates)
        while queue and len(found) < limit:
            sm = queue.popleft()
            if sm in visited:
                continue
            visited.add(sm)
            try:
                data, _ctype, _final, _hdr = self.fetch(sm)
            except Exception:
                continue
            text = data.decode("utf-8", "replace")
            locs = [html_mod.unescape(x) for x in
                    re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I)]
            if not locs:
                continue
            if "<sitemapindex" in text.lower() or all(
                    x.endswith((".xml", ".xml.gz")) for x in locs[:3]):
                for loc in locs[:200]:
                    if self.host_of(loc) in self.allowed_hosts:
                        queue.append(loc)
                continue
            for loc in locs:
                if self.host_of(loc) in self.allowed_hosts:
                    found.append(loc)
                    if len(found) >= limit:
                        break
        return found

    @staticmethod
    def host_of(url):
        return (urllib.parse.urlparse(url).hostname or "").lower()

    def is_document(self, url, ctype=""):
        path = urllib.parse.urlparse(url).path.lower()
        ext = os.path.splitext(path)[1]
        if ext in DOC_EXTENSIONS:
            return True
        if ext in (".html", ".htm", ".php", ".aspx", ".jsp", ".shtml"):
            if not ctype or "text/" in ctype or "html" in ctype:
                return False
        low = url.lower()
        if any(hint in low for hint in DOC_HINTS):
            if ext not in (".html", ".htm", ".php", ".aspx", ".jsp"):
                return True
        if ctype and "text/html" not in ctype and "xml" not in ctype:
            if any(k in ctype for k in ("pdf", "zip", "rar", "7z", "octet-stream",
                                        "msword", "ms-excel", "spreadsheet",
                                        "presentation", "csv", "opendocument")):
                return True
        return False

    @staticmethod
    def should_skip(url):
        path = urllib.parse.urlparse(url).path.lower()
        return os.path.splitext(path)[1] in SKIP_EXTENSIONS

    def allowed(self, url):
        if self.host_of(url) not in self.allowed_hosts:
            return False
        if self.should_skip(url):
            return False
        if any(p.search(url) for p in self.exclude):
            return False
        if self.include and not any(p.search(url) for p in self.include):
            return False
        return self.robots_allows(url)

    def filename_for(self, url, ctype="", headers=None):
        name = ""
        if headers:
            disp = headers.get("Content-Disposition") or ""
            match = re.search(r"filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)", disp)
            if match:
                name = sanitize_name(urllib.parse.unquote(match.group(1).strip()))
            else:
                match = re.search(r"filename\s*=\s*\"?([^\";]+)\"?", disp, re.I)
                if match:
                    raw = match.group(1).strip()
                    try:
                        raw = raw.encode("latin-1").decode("utf-8")
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        pass
                    name = sanitize_name(raw)
        if not name:
            path = urllib.parse.urlparse(url).path
            base = os.path.basename(path.rstrip("/"))
            name = sanitize_name(base) if base else ""
        if not os.path.splitext(name)[1]:
            ext = ""
            for key, val in (("pdf", ".pdf"), ("spreadsheet", ".xlsx"),
                             ("ms-excel", ".xls"), ("zip", ".zip"),
                             ("rar", ".rar"), ("7z", ".7z"), ("word", ".docx"),
                             ("presentation", ".pptx"), ("csv", ".csv"),
                             ("json", ".json")):
                if key in ctype:
                    ext = val
                    break
            name = (name or "فایل") + ext
        return f"{url_hash(url)}_{name}"

    def _sub(self, *parts):
        path = os.path.join(self.dir, *parts)
        os.makedirs(path, exist_ok=True)
        return path

    def save_document(self, url, data, ctype, headers=None):
        name = self.filename_for(url, ctype, headers)
        if not os.path.splitext(name)[1]:
            name += sniff_ext(data)
        path = os.path.join(self._sub("فایل‌ها"), name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def save_page(self, url, data, parser):
        pages = self._sub("صفحات")
        title = sanitize_name(parser.title.strip(), 80) or url_hash(url)
        stem = f"{url_hash(url)}_{title}"
        html_path = os.path.join(pages, stem + ".html")
        with open(html_path, "wb") as fh:
            fh.write(data)
        txt_path = os.path.join(pages, stem + ".txt")
        with open(txt_path, "w", encoding="utf-8") as fh:
            fh.write(f"URL: {url}\nعنوان: {parser.title.strip()}\n{'=' * 70}\n")
            fh.write(parser.text)
        table_paths, json_paths = [], []
        if self.extract_tables and parser.tables:
            tables_dir = self._sub("جدول‌ها")
            for idx, table in enumerate(parser.tables[:25], 1):
                tpath = os.path.join(tables_dir, f"{stem}_t{idx}.csv")
                with open(tpath, "w", newline="", encoding="utf-8-sig") as fh:
                    csv.writer(fh).writerows(table)
                table_paths.append(tpath)
        if parser.json_blobs:
            data_dir = self._sub("داده-جاسازی‌شده")
            for idx, blob in enumerate(parser.json_blobs[:10], 1):
                jpath = os.path.join(data_dir, f"{stem}_j{idx}.json")
                with open(jpath, "w", encoding="utf-8") as fh:
                    fh.write(blob)
                json_paths.append(jpath)
        return {"html": html_path, "txt": txt_path,
                "tables": table_paths, "json": json_paths}

    def crawl(self):
        os.makedirs(self.dir, exist_ok=True)
        log(f"=== شروع: {self.name}")
        self.load_robots()
        queue = deque()
        for url in self.site.get("start_urls", []):
            norm = normalize_url(url, url)
            if norm:
                queue.append((norm, 0, None))
        if self.use_sitemap:
            sm = self.sitemap_urls()
            if sm:
                log(f"    sitemap: {len(sm)} آدرس کشف شد")
                for url in sm:
                    queue.append((url, 1, "sitemap"))

        while queue and self.stats["pages"] < self.max_pages:
            url, depth, referrer = queue.popleft()
            if url in self.seen:
                continue
            self.seen.add(url)
            if not self.allowed(url):
                continue
            try:
                self.process(url, depth, queue, referrer)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                self.stats["errors"] += 1
                self.consecutive_failures += 1
                self.manifest["failed"][url_hash(url)] = {
                    "url": url, "error": f"{type(exc).__name__}: {str(exc)[:150]}"}
                log(f"    خطا: {url[:75]} :: {type(exc).__name__} {str(exc)[:50]}")
                if self.consecutive_failures >= 8:
                    log(f"    {self.consecutive_failures} خطای پیاپی؛ توقف خزش "
                        f"{self.name} (احتمالاً دسترسی از این شبکه مسدود است)")
                    self.aborted = True
                    break
            if (self.stats["pages"] + self.stats["files"]) % 10 == 0:
                self.save_manifest()

        self.save_manifest()
        self.write_discovered()
        self.h.flush_metadata()
        log(f"=== پایان {self.name}: {self.stats['pages']} صفحه، "
            f"{self.stats['files']} فایل، {self.stats['errors']} خطا")

    def process(self, url, depth, queue, referrer=None):
        key = url_hash(url)
        known = self.manifest["downloaded"].get(key)
        if known and known.get("type") == "file":
            return
        if known and known.get("type") == "page":
            self.revisit(known, depth, queue)
            return

        data, ctype, final, headers = self.fetch(url)
        if self.looks_like_page(final, ctype):
            return self.handle_page(url, data, final, depth, queue, referrer)
        if self.is_document(url, ctype):
            digest = hashlib.sha1(data).hexdigest()
            seen_hashes = self.manifest.setdefault("hashes", {})
            if digest in seen_hashes:
                self.manifest["downloaded"][key] = {
                    "url": url, "path": seen_hashes[digest], "type": "file",
                    "size": len(data), "duplicate": True, "referrer": referrer}
                return
            path = self.save_document(url, data, ctype, headers)
            seen_hashes[digest] = path
            self.stats["files"] += 1
            self.stats["bytes"] += len(data)
            self.manifest["downloaded"][key] = {
                "url": url, "path": path, "type": "file", "size": len(data),
                "sha1": digest, "referrer": referrer}
            self.h.add_index_row([self.name, "فایل", url, path, len(data)])
            self.discovered.append({"url": url, "type": "file", "depth": depth})
            self.h.write_meta({
                "id": key,
                "type": "file",
                "source_site": self.name,
                "source_site_url": self.site.get("start_urls", [""])[0],
                "source_page": referrer or "",
                "source_url": url,
                "final_url": final,
                "title": os.path.basename(path),
                "file_name": os.path.basename(path),
                "local_path": os.path.relpath(path, self.h.root),
                "content_type": ctype,
                "size_bytes": len(data),
                "sha1": digest,
                "depth": depth,
            })
            log(f"    فایل ({len(data) // 1024} KB): {os.path.basename(path)[:70]}")
            return
        return self.handle_page(url, data, final, depth, queue, referrer)

    @staticmethod
    def looks_like_page(url, ctype):
        """آیا پاسخ یک صفحه HTML/XML است؟ (نوع واقعی ملاک است)"""
        if ctype:
            if "text/html" in ctype or "xhtml" in ctype:
                return True
            if "xml" in ctype:
                path = urllib.parse.urlparse(url).path.lower()
                return os.path.splitext(path)[1] not in DOC_EXTENSIONS
            return False
        path = urllib.parse.urlparse(url).path.lower()
        return os.path.splitext(path)[1] in ("", ".html", ".htm", ".php", ".aspx")

    def handle_page(self, url, data, final, depth, queue, referrer=None):
        key = url_hash(url)
        parser = PageParser()
        try:
            parser.feed(decode_html(data))
        except Exception:
            pass
        saved = self.save_page(url, data, parser)
        path = saved["html"]
        links = []
        for href in parser.links[:3000]:
            norm = normalize_url(final, href)
            if norm:
                links.append(norm)
        self.manifest["downloaded"][key] = {
            "url": url, "path": path, "type": "page",
            "title": parser.title.strip()[:200], "link_count": len(links),
            "referrer": referrer}
        self.h.add_index_row([self.name, "صفحه", url, path, len(data)])
        self.discovered.append({"url": url, "type": "page", "depth": depth,
                                "title": parser.title.strip()[:150]})
        self.h.write_meta({
            "id": key,
            "type": "page",
            "source_site": self.name,
            "source_site_url": self.site.get("start_urls", [""])[0],
            "source_page": referrer or "",
            "source_url": url,
            "final_url": final,
            "title": parser.title.strip()[:300],
            "file_name": os.path.basename(path),
            "local_path": os.path.relpath(path, self.h.root),
            "text_path": os.path.relpath(saved["txt"], self.h.root),
            "content_type": "text/html",
            "size_bytes": len(data),
            "sha1": hashlib.sha1(data).hexdigest(),
            "depth": depth,
        })
        for idx, tpath in enumerate(saved["tables"], 1):
            self.h.write_meta({
                "id": f"{key}-t{idx}",
                "type": "table",
                "source_site": self.name,
                "source_site_url": self.site.get("start_urls", [""])[0],
                "source_page": url,
                "source_url": url,
                "final_url": final,
                "title": f"{parser.title.strip()[:200]} (جدول {idx})",
                "file_name": os.path.basename(tpath),
                "local_path": os.path.relpath(tpath, self.h.root),
                "content_type": "text/csv",
                "size_bytes": os.path.getsize(tpath),
                "depth": depth,
                "fragment": f"table-{idx}",
            })
        for idx, jpath in enumerate(saved["json"], 1):
            self.h.write_meta({
                "id": f"{key}-j{idx}",
                "type": "embedded_json",
                "source_site": self.name,
                "source_site_url": self.site.get("start_urls", [""])[0],
                "source_page": url,
                "source_url": url,
                "final_url": final,
                "title": f"{parser.title.strip()[:200]} (داده {idx})",
                "file_name": os.path.basename(jpath),
                "local_path": os.path.relpath(jpath, self.h.root),
                "content_type": "application/json",
                "size_bytes": os.path.getsize(jpath),
                "depth": depth,
                "fragment": f"json-{idx}",
            })
        self.stats["pages"] += 1
        if self.stats["pages"] % 25 == 0:
            log(f"    {self.stats['pages']} صفحه / {self.stats['files']} فایل ...")
        self.enqueue_links(links, final, depth, queue)

    def revisit(self, known, depth, queue):
        """ادامه خزش بدون درخواست شبکه: لینک‌ها از HTML ذخیره‌شده خوانده می‌شوند."""
        self.stats["pages"] += 1
        links = known.get("links")
        if not links:
            links = []
            path = known.get("path")
            if path and os.path.exists(path):
                try:
                    with open(path, "rb") as fh:
                        data = fh.read()
                    parser = PageParser()
                    parser.feed(decode_html(data))
                    links = [normalize_url(known.get("url", ""), h)
                             for h in parser.links[:3000]]
                except Exception:
                    links = []
        self.enqueue_links([l for l in links if l], known.get("url", ""),
                           depth, queue)

    def enqueue_links(self, links, base, depth, queue):
        if depth >= self.max_depth:
            return
        for link in links:
            norm = normalize_url(base, link)
            if not norm or norm in self.seen:
                continue
            if self.host_of(norm) not in self.allowed_hosts:
                continue
            if self.is_document(norm):
                queue.appendleft((norm, depth + 1, base))
            else:
                queue.append((norm, depth + 1, base))

    def write_discovered(self):
        path = os.path.join(self.dir, "_discovered.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"site": self.name, "count": len(self.discovered),
                       "items": self.discovered}, fh, ensure_ascii=False, indent=1)


class Harvester:
    def __init__(self, config, use_ai=False, limit=None, delay=None):
        self.config = config
        root = config.get("output_root") or "."
        self.root = root if os.path.isabs(root) else os.path.abspath(
            os.path.join(os.getcwd(), root))
        self.timeout = config.get("timeout", 45)
        self.retries = config.get("retries", 3)
        self.max_file_bytes = config.get("max_file_mb", 300) * 1024 * 1024
        self.limit_override = limit
        self.default_max_pages = config.get("max_pages_per_site", 5000)
        self.default_delay = delay if delay is not None else config.get("delay", 0.4)
        self.use_ai = use_ai and bool(config.get("ai", {}).get("api_key"))
        self.index_path = os.path.join(self.root, "فهرست-دانلودها.csv")
        self.index_lock = threading.Lock()
        self.meta_jsonl = os.path.join(self.root, "metadata.jsonl")
        self.meta_csv = os.path.join(self.root, "metadata.csv")
        self.meta_lock = threading.Lock()
        self._repair_meta_tail()
        self.rows = []
        self.crawlers = []

    def _repair_meta_tail(self):
        """اگر اجرای قبلی وسط نوشتن قطع شده باشد، خط ناقص را جدا می‌کند."""
        if not os.path.exists(self.meta_jsonl) or os.path.getsize(self.meta_jsonl) == 0:
            return
        with open(self.meta_jsonl, "rb+") as fh:
            fh.seek(-1, os.SEEK_END)
            if fh.read(1) != b"\n":
                fh.write(b"\n")

    def write_meta(self, record):
        """یک رکورد متادیتا را به‌صورت JSONL ثبت می‌کند."""
        record = dict(record)
        if not record.get("source_domain"):
            record["source_domain"] = urllib.parse.urlsplit(
                record.get("source_url", "")).hostname or ""
        record.setdefault("downloaded_at",
                          datetime.now().isoformat(timespec="seconds"))
        with self.meta_lock:
            os.makedirs(self.root, exist_ok=True)
            with open(self.meta_jsonl, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def flush_metadata(self):
        """metadata.jsonl را به CSV تبدیل می‌کند (برای استفاده در نرم‌افزار دیگر)."""
        if not os.path.exists(self.meta_jsonl):
            return
        columns = ["id", "type", "source_site", "source_site_url", "source_page",
                   "source_domain", "source_url", "final_url", "title",
                   "file_name", "local_path", "text_path", "content_type",
                   "size_bytes", "sha1",
                   "downloaded_at", "depth", "fragment"]
        seen = {}
        with open(self.meta_jsonl, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                seen[rec.get("id") or rec.get("local_path")] = rec
        with open(self.meta_csv, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for rec in seen.values():
                writer.writerow(rec)
        log(f"متادیتا: {len(seen)} رکورد → {self.meta_csv}")

    def add_index_row(self, row):
        with self.index_lock:
            self.rows.append(row)

    def flush_index(self):
        with self.index_lock:
            if not self.rows:
                return
            exists = os.path.exists(self.index_path)
            with open(self.index_path, "a", newline="", encoding="utf-8-sig") as fh:
                writer = csv.writer(fh)
                if not exists:
                    writer.writerow(["سایت", "نوع", "آدرس", "مسیر", "حجم (بایت)"])
                writer.writerows(self.rows)
            self.rows.clear()

    def run(self, site_filter=None, parallel=1):
        os.makedirs(self.root, exist_ok=True)
        sites = [s for s in self.config["sites"]
                 if not site_filter or site_filter in s["folder"]
                 or site_filter in s["name"]]
        if not sites:
            log("سایتی با این فیلتر پیدا نشد.")
            return
        self.crawlers = [SiteCrawler(self, s) for s in sites]
        try:
            if parallel > 1:
                pending = deque(self.crawlers)
                running = []
                while pending or running:
                    while pending and len(running) < parallel:
                        crawler = pending.popleft()
                        th = threading.Thread(target=self._safe_crawl, args=(crawler,))
                        th.start()
                        running.append(th)
                        time.sleep(0.5)
                    running[0].join()
                    running.pop(0)
            else:
                for crawler in self.crawlers:
                    self._safe_crawl(crawler)
        except KeyboardInterrupt:
            log("توقف توسط کاربر؛ وضعیت ذخیره می‌شود.")
        finally:
            for crawler in self.crawlers:
                try:
                    crawler.save_manifest()
                except Exception:
                    pass
            self.flush_index()
            self.flush_metadata()
            self.write_discovered_config()
            log("تمام شد.")

    @staticmethod
    def _safe_crawl(crawler):
        try:
            crawler.crawl()
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            log(f"خطای کلی در {crawler.name}: {type(exc).__name__}: {str(exc)[:120]}")

    def write_discovered_config(self):
        """کانفیگ کامل و قابل‌استفاده را از نتایج خزش می‌سازد."""
        out = {"output_root": self.root,
               "max_pages_per_site": self.config.get("max_pages_per_site", 6000),
               "max_file_mb": self.config.get("max_file_mb", 400),
               "timeout": self.timeout, "retries": self.retries,
               "delay": self.default_delay, "ai": self.config.get("ai", {}),
               "_generated": datetime.now().isoformat(timespec="seconds"),
               "sites": []}
        for crawler in self.crawlers:
            pages = [d["url"] for d in crawler.discovered
                     if d["type"] == "page" and d.get("depth", 0) <= 2]
            groups = {}
            for url in pages:
                parts = [p for p in urllib.parse.urlsplit(url).path.split("/") if p]
                key = parts[0] if parts else "/"
                groups.setdefault(key, []).append(url)
            site = dict(crawler.site)
            site.pop("_sitemaps_from_robots", None)
            site["start_urls"] = pages[:120] or crawler.site.get("start_urls", [])
            site["_stats"] = crawler.stats
            site["_sections"] = {k: len(v) for k, v in sorted(groups.items())}
            out["sites"].append(site)
        path = os.path.join(HERE, "config.discovered.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=1)
        log(f"کانفیگ کشف‌شده ذخیره شد: {path}")


def main():
    if sys.stdout and hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                      errors="replace")
    parser = argparse.ArgumentParser(description="جمع‌آوری کامل محتوای سایت‌های آماری")
    parser.add_argument("--site", help="فقط سایتی که نام یا پوشه‌اش شامل این عبارت است")
    parser.add_argument("--limit", type=int, help="سقف صفحات هر سایت")
    parser.add_argument("--delay", type=float, help="فاصله بین درخواست‌ها (ثانیه)")
    parser.add_argument("--parallel", type=int, default=1, help="تعداد سایت هم‌زمان")
    parser.add_argument("--ai", action="store_true", help="دسته‌بندی هوشمند")
    parser.add_argument("--config", default=CONFIG_PATH)
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as fh:
        config = json.load(fh)
    Harvester(config, use_ai=args.ai, limit=args.limit, delay=args.delay).run(
        site_filter=args.site, parallel=args.parallel)


if __name__ == "__main__":
    main()
