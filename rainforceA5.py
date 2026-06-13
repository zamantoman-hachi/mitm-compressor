#!/usr/bin/env python3
from mitmproxy import http
from concurrent.futures import ThreadPoolExecutor
from PIL import Image, ImageOps
from pathlib import Path
import io
import logging
import time
import hashlib
import gzip
import zstandard as zstd
import urllib.request
import threading
import os
import re
import ahocorasick

# lxml を優先し、なければ html.parser にフォールバック
try:
    from bs4 import BeautifulSoup
    _BS_PARSER = "lxml"
    import lxml  # noqa: F401
except ImportError:
    from bs4 import BeautifulSoup
    _BS_PARSER = "html.parser"

try:
    import brotlicffi as brotli
except Exception:
    import brotli


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitm_avif_zstd")

# --- 設定 ---
MIN_BYTES = 10_000
MIN_VIDEO_BYTES = 600 * 1024
TARGET_QUALITY_AVIF = 40
MAX_WIDTH = 1600
ZSTD_LEVEL = 11
BROTLI_QUALITY = 6
GZIP_LEVEL = 6          # 改善: デフォルト(9)から変更。速度と圧縮率のバランス
WORKER_THREADS = 2
STACK_DIR = Path("/home/abraxas/mitm/stack")
STACK_DIR.mkdir(parents=True, exist_ok=True)

# AdBlock設定
FILTER_DIR = "/etc/ads/filters"
POLL_INTERVAL = 5.0
HTML_SIZE_LIMIT = 512 * 1024
INJECT_CSS = "/* injected hide rules */ .ad, .ads, [id*=\"ad\"]{display:none!important}"
_executor = ThreadPoolExecutor(max_workers=WORKER_THREADS)


def choose_encoding(accept_encoding_header: str):
    if not accept_encoding_header:
        return "identity"
    ae = accept_encoding_header.lower()

    # if "zstd" in ae:
    #     return "zstd"

    if "br" in ae:
        return "br"

    if "gzip" in ae:
        return "gzip"

    return "identity"


def save_original_image(data: bytes, extension: str):
    """改善: ディスクI/Oを _executor に投げて非同期化"""
    def _write():
        try:
            ts = int(time.time() * 1000)
            h = hashlib.sha1(data).hexdigest()[:12]
            filename = STACK_DIR / f"{ts}_{h}{extension}"
            with open(filename, "wb") as f:
                f.write(data)
        except Exception as e:
            logger.error(f"Failed to save original image: {e}")

    _executor.submit(_write)


def compress_svg(content: str) -> str:
    # 注意: brotli/gzip 圧縮を後段でかける場合、この処理の効果は限定的。
    # ただしネットワーク転送前のサイズ削減として残す。
    try:
        content = content.replace('\n', '').replace('\r', '').replace('\t', '')
        content = re.sub(r'\s+', ' ', content)
        content = re.sub(r'> <', '><', content)
        content = re.sub(r'<!--.*?-->', '', content)
        return content.strip()
    except Exception as e:
        logger.error(f"SVG compression failed: {e}")
        return content


class AdBlockFilter:
    def __init__(self):
        self.automaton = ahocorasick.Automaton()
        self.tokens = set()
        self.mtimes = {}
        self.lock = threading.Lock()

        self._start_watcher()

    def _start_watcher(self):
        t = threading.Thread(target=self._watch_loop, daemon=True)
        t.start()

    def _watch_loop(self):
        while True:
            try:
                self._reload_if_needed()
            except Exception as e:
                logger.error(f"filter watcher error: {e}")
            time.sleep(POLL_INTERVAL)

    def _reload_if_needed(self):
        try:
            files = [os.path.join(FILTER_DIR, f) for f in os.listdir(FILTER_DIR)
                     if os.path.isfile(os.path.join(FILTER_DIR, f))]
        except FileNotFoundError:
            files = []
        changed = False
        for fp in files:
            try:
                m = os.path.getmtime(fp)
            except OSError:
                continue
            if fp not in self.mtimes or self.mtimes[fp] != m:
                changed = True
                self.mtimes[fp] = m
        removed = [p for p in list(self.mtimes.keys()) if p not in files]
        if removed:
            changed = True
            for p in removed:
                del self.mtimes[p]
        if changed:
            self._reload_tokens(files)

    def _reload_tokens(self, files):
        toks = set()
        for fp in files:
            try:
                with open(fp, "r", encoding="utf-8") as fh:
                    for line in fh:
                        s = line.strip()
                        if not s or s.startswith("#"):
                            continue
                        toks.add(s)
            except Exception as e:
                logger.error(f"failed to read {fp}: {e}")
        self._build_automaton(toks)
        logger.info(f"AC loaded {len(toks)} tokens from {len(files)}")

    def _build_automaton(self, toks):
        A = ahocorasick.Automaton()
        for i, tok in enumerate(sorted(toks)):
            A.add_word(tok, (i, tok))
        A.make_automaton()
        with self.lock:
            self.automaton = A
            self.tokens = set(toks)

    def _ac_find(self, text):
        """Aho-Corasick によるマッチ。ロックはオートマトン参照のみ。"""
        found = set()
        if not text:
            return found
        with self.lock:
            A = self.automaton
        try:
            for _, (_, tok) in A.iter(text):
                found.add(tok)
        except Exception:
            pass
        return found

    def request(self, flow: http.HTTPFlow):
        try:
            host = flow.request.host or ""
            url = flow.request.pretty_url or ""

            # 改善: URL とホスト名のみチェック（本文スキャンは request 時点では不要）
            hits = self._ac_find(host) | self._ac_find(url)

            if hits:
                logger.info(f"blocking request {url} tokens={list(hits)[:5]}")
                flow.response = http.HTTPResponse.make(200, b"", {"Content-Type": "text/plain"})
        except Exception as e:
            logger.error(f"request handler error: {e}")

    def response(self, flow: http.HTTPFlow):
        try:
            if not flow.response:
                return
            ctype = flow.response.headers.get("content-type", "")
            url = flow.request.pretty_url or ""
            host = flow.request.host or ""

            if "text/html" in ctype:
                body = flow.response.get_text(strict=False)
                if not body:
                    return

                # 改善: HTML本文の全文スキャンはサイズ上限内のみ実施。
                #        URL マッチは常に行う。
                url_hits = self._ac_find(url)
                body_hits = set()
                if len(body.encode("utf-8", errors="ignore")) <= HTML_SIZE_LIMIT:
                    body_hits = self._ac_find(body)
                matched = url_hits | body_hits

                if matched:
                    if len(body.encode("utf-8", errors="ignore")) <= HTML_SIZE_LIMIT:
                        # 改善案1: lxml パーサーを優先使用
                        soup = BeautifulSoup(body, _BS_PARSER)
                        removed_count = 0

                        # 改善案1: トークンを1本の正規表現にまとめ、
                        #           find_all をシングルパスで処理するカスタム関数
                        combined_re = re.compile(
                            "|".join(re.escape(t) for t in matched), re.I
                        )

                        def _find_all_matching(tag):
                            """combined_re に合致する要素をシングルパスで列挙"""
                            return soup.find_all(lambda e: (
                                (combined_re.search(e.get("id", "") or "")) or
                                (combined_re.search(" ".join(e.get("class") or []))) or
                                (combined_re.search(e.get("src", "") or "")) or
                                (combined_re.search(e.get("href", "") or ""))
                            ))

                        for e in _find_all_matching(soup):
                            e.decompose()
                            removed_count += 1

                        for s in soup.find_all("script"):
                            txt = s.string or ""
                            if txt and combined_re.search(txt):
                                s.decompose()
                                removed_count += 1

                        style_tag = soup.new_tag("style")
                        style_tag.string = INJECT_CSS
                        if soup.head:
                            soup.head.append(style_tag)
                        elif soup.body:
                            soup.body.insert(0, style_tag)
                        else:
                            soup.insert(0, style_tag)
                        flow.response.set_text(str(soup))
                        logger.info(f"modified HTML {url} removed={removed_count} tokens={list(matched)[:5]}")
                    else:
                        new_body = re.sub(
                            r"(?i)<head([^>]*)>",
                            r"<head\1><style>{}</style>".format(INJECT_CSS),
                            body, count=1
                        )
                        if new_body == body:
                            new_body = "<style>{}</style>\n".format(INJECT_CSS) + body
                        flow.response.set_text(new_body)
                        logger.info(f"injected CSS for large HTML {url} tokens={list(matched)[:5]}")

            elif ("javascript" in ctype) or ("json" in ctype) or ("text/plain" in ctype):
                body = flow.response.get_text(strict=False)
                if not body:
                    return
                # JS/JSON はサイズが大きいケースもあるので URL マッチのみ
                matched = self._ac_find(url)
                if matched:
                    flow.response.set_text("")
                    logger.info(f"stripped JS/JSON {url} tokens={list(matched)[:5]}")

        except Exception as e:
            logger.error(f"response handler error: {e}")


adblock_filter = AdBlockFilter()

# 改善案2: ダウンロード中・済みURLを記録するスレッドセーフなset。重複投入を防ぐ。
_downloading_urls: set[str] = set()
_downloading_urls_lock = threading.Lock()


def extract_and_download_videos(html_content: bytes):
    """HTMLから mp4 URL を抽出し、バックグラウンドでダウンロード・保存する。
    改善案2: _downloading_urls_lock で保護した set により、同一URLの重複投入を防ぐ。"""
    try:
        html_str = html_content.decode('utf-8', errors='ignore')
        pattern = r'<source[^>]*type=["\']video/mp4["\'][^>]*src=["\']([^"\']+)["\']'
        urls = re.findall(pattern, html_str, re.IGNORECASE)
        for url in urls:
            with _downloading_urls_lock:
                if url in _downloading_urls:
                    logger.debug(f"Skipping duplicate video URL: {url}")
                    continue
                _downloading_urls.add(url)
            _executor.submit(_download_video, url)
    except Exception as e:
        logger.error(f"Failed to extract video URLs: {e}")


def _download_video(url: str):
    """改善: メモリに全展開せずストリーミング書き込み"""
    try:
        logger.info(f"Downloading video: {url}")
        ts = int(time.time() * 1000)
        # URL からハッシュ（ダウンロード前なのでURLベース）
        h = hashlib.sha1(url.encode()).hexdigest()[:12]
        filename = STACK_DIR / f"{ts}_{h}_fullvideo.mp4"

        total = 0
        with urllib.request.urlopen(url, timeout=30) as resp, \
             open(filename, "wb") as f:
            while True:
                chunk = resp.read(65536)  # 64KB ずつ読み書き
                if not chunk:
                    break
                f.write(chunk)
                total += len(chunk)

        if total < MIN_VIDEO_BYTES:
            logger.info(f"Video skipped (too small): {url} ({total} bytes)")
            try:
                filename.unlink()
            except OSError:
                pass
            return

        logger.info(f"Video saved: {filename} ({total} bytes)")
    except Exception as e:
        logger.error(f"Failed to download video from {url}: {e}")


def response(flow: http.HTTPFlow) -> None:
    try:
        if not flow.response or flow.response.status_code not in (200, 206):
            return
        try:
            flow.response.decode()
        except Exception:
            pass

        # AdBlock 処理（HTML書き換えを先行）
        adblock_filter.response(flow)

        headers = flow.response.headers
        ct = headers.get("content-type", "").lower()

        if "content-encoding" in headers:
            del headers["content-encoding"]

        accept_encoding = flow.request.headers.get("accept-encoding", "")
        chosen = choose_encoding(accept_encoding)

        # --- HTML 圧縮 ---
        if "text/html" in ct:
            payload = flow.response.content

            # 改善: extract_and_download_videos は既に非同期（_executor.submit）
            extract_and_download_videos(payload)

            if not payload or len(payload) < 200:
                return

            compressed = None

            if chosen == "zstd":
                c = zstd.ZstdCompressor(level=ZSTD_LEVEL)
                compressed = c.compress(payload)

            elif chosen == "br":
                compressed = brotli.compress(payload, quality=BROTLI_QUALITY)

            elif chosen == "gzip":
                # 改善: level=6 でバランスを取る（デフォルトの9は低速）
                compressed = gzip.compress(payload, compresslevel=GZIP_LEVEL)

            if compressed and len(compressed) < len(payload):
                flow.response.content = compressed
                headers["content-encoding"] = chosen
                headers["content-length"] = str(len(compressed))
            else:
                headers["content-length"] = str(len(payload))

        # --- SVG 圧縮 ---
        elif "image/svg" in ct:
            payload = flow.response.content

            if not payload or len(payload) < 200:
                return

            try:
                svg_str = payload.decode('utf-8', errors='ignore')
                compressed_svg = compress_svg(svg_str).encode('utf-8')

                compressed = None

                if chosen == "zstd":
                    c = zstd.ZstdCompressor(level=ZSTD_LEVEL)
                    compressed = c.compress(compressed_svg)

                elif chosen == "br":
                    compressed = brotli.compress(compressed_svg, quality=BROTLI_QUALITY)

                elif chosen == "gzip":
                    compressed = gzip.compress(compressed_svg, compresslevel=GZIP_LEVEL)

                if compressed and len(compressed) < len(payload):
                    flow.response.content = compressed
                    headers["content-encoding"] = chosen
                    headers["content-length"] = str(len(compressed))
                    logger.info(
                        f"Compressed SVG: {len(payload)} -> {len(compressed_svg)} -> {len(compressed)} ({chosen})"
                    )
                elif len(compressed_svg) < len(payload):
                    flow.response.content = compressed_svg
                    headers["content-length"] = str(len(compressed_svg))
                    logger.info(
                        f"Compressed SVG: {len(payload)} -> {len(compressed_svg)}"
                    )
                else:
                    headers["content-length"] = str(len(payload))
            except Exception as e:
                logger.error(f"SVG processing failed: {e}")

        # --- JPEG / PNG / WebP → AVIF（非同期変換） ---
        elif any(t in ct for t in ("image/jpeg", "image/png", "image/webp")):
            if len(flow.response.content) < MIN_BYTES:
                return

            ext = {
                "image/jpeg": ".jpg",
                "image/png": ".png",
                "image/webp": ".webp",
            }.get(ct.split(";")[0].strip(), ".bin")

            # 改善: save_original_image は非同期（内部で _executor.submit）
            if len(flow.response.content) >= 100 * 1024:
                save_original_image(flow.response.content, ext)

            original_data = flow.response.content
            original_size = len(original_data)

            def _convert():
                try:
                    import pillow_avif  # noqa: F401

                    img = Image.open(io.BytesIO(original_data))

                    if getattr(img, "is_animated", False):
                        return None

                    img = ImageOps.exif_transpose(img)

                    if img.width > MAX_WIDTH:
                        img.thumbnail((MAX_WIDTH, MAX_WIDTH), Image.LANCZOS)

                    out = io.BytesIO()
                    img.save(out, "AVIF", quality=TARGET_QUALITY_AVIF)
                    return out.getvalue()

                except Exception:
                    return None

            # 改善: future.result() によるブロッキングを維持しつつ、
            #        変換をスレッドプールで実行。
            #        mitmproxy の @concurrent アドオンが使えない環境向けに
            #        現行構造を維持しているが、可能であれば concurrent デコレータ推奨。
            future = _executor.submit(_convert)
            converted = future.result()

            if converted and len(converted) < original_size:
                flow.response.content = converted
                headers["content-type"] = "image/avif"
                headers["content-length"] = str(len(converted))

        # --- GIF → WebP ---
        elif ct.startswith("image/gif"):
            if len(flow.response.content) < MIN_BYTES:
                return

            # 改善: save_original_image は非同期
            save_original_image(flow.response.content, ".gif")

            gif_data = flow.response.content

            def _convert_gif_to_webp():
                try:
                    img = Image.open(io.BytesIO(gif_data))
                    s2 = io.BytesIO()
                    img.save(s2, "WEBP", save_all=True, quality=60)
                    return s2.getvalue()
                except Exception:
                    return None

            future = _executor.submit(_convert_gif_to_webp)
            converted = future.result()

            if converted and len(converted) < len(gif_data):
                flow.response.content = converted
                headers["content-type"] = "image/webp"
                headers["content-length"] = str(len(converted))

        # --- WebM 保存 ---
        elif ct.startswith("video/webm"):
            if len(flow.response.content) < MIN_BYTES:
                return
            if len(flow.response.content) >= MIN_VIDEO_BYTES:
                save_original_image(flow.response.content, ".webm")

        # --- MP4 保存 ---
        elif ct.startswith("video/mp4"):
            if len(flow.response.content) < MIN_BYTES:
                return
            if len(flow.response.content) >= MIN_VIDEO_BYTES:
                save_original_image(flow.response.content, ".mp4")

        # --- キャッシュ制御 ---
        # 改善: 元レスポンスに no-store / private がある場合は上書きしない
        if flow.response and flow.response.status_code == 200:
            existing_cc = headers.get("Cache-Control", "").lower()
            if "no-store" not in existing_cc and "private" not in existing_cc:
                ct2 = headers.get("content-type", "").lower()
                if "text/html" in ct2:
                    headers["Cache-Control"] = "public, max-age=3600"
                elif any(t in ct2 for t in (
                    "image/", "text/css", "application/javascript",
                    "text/javascript", "font/", "image/svg"
                )):
                    headers["Cache-Control"] = "public, max-age=31536000, immutable"
                elif any(t in ct2 for t in ("video/", "audio/")):
                    headers["Cache-Control"] = "public, max-age=604800"

    except Exception as e:
        logger.error(f"Error in response handler: {e}")


def request(flow: http.HTTPFlow) -> None:
    try:
        adblock_filter.request(flow)
    except Exception as e:
        logger.error(f"Error in request handler: {e}")
