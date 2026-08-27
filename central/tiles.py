"""On-demand OpenStreetMap raster tile cache for the device map.

Tiles are fetched from tile.openstreetmap.org only when the map actually
asks for them. Cached copies live under data/tiles/{z}/{x}/{y}.png and are
kept at least 7 days, then revalidated with conditional requests. There is
no prefetch or bulk download — that is forbidden by OSM's tile policy.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from central import __version__
from central.config import data_dir

OSM_TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
MAX_ZOOM = 19
MIN_CACHE_SECONDS = 7 * 24 * 3600
FETCH_TIMEOUT = 20
MAX_FETCHES = 2
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
USER_AGENT = (
    f"SentinelCentral/{__version__} "
    "(personal home dashboard; +https://github.com/datagod/sentinel)"
)

_FETCH_GATE = threading.Semaphore(MAX_FETCHES)
_LOCKS_GUARD = threading.Lock()
_TILE_LOCKS: dict[tuple[int, int, int], threading.Lock] = {}


class TileError(Exception):
    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


def tiles_dir(settings: dict[str, Any] | None = None) -> Path:
    path = data_dir(settings) / "tiles"
    path.mkdir(parents=True, exist_ok=True)
    return path


def valid_tile(z: int, x: int, y: int) -> bool:
    if not isinstance(z, int) or not isinstance(x, int) or not isinstance(y, int):
        return False
    if z < 0 or z > MAX_ZOOM:
        return False
    n = 1 << z
    return 0 <= x < n and 0 <= y < n


def tile_path(cache_root: Path, z: int, x: int, y: int) -> Path:
    return cache_root / str(z) / str(x) / f"{y}.png"


def get_tile(
    cache_root: Path,
    z: int,
    x: int,
    y: int,
    *,
    referer: str = "",
) -> tuple[Path, str, int]:
    """Return (png_path, source, browser_max_age).

    source is hit, miss, revalidate, or stale.
    """
    if not valid_tile(z, x, y):
        raise TileError("invalid tile coordinates", status=404)
    lock = _lock_for(z, x, y)
    with lock:
        return _get_tile_locked(cache_root, z, x, y, referer=referer)


def _lock_for(z: int, x: int, y: int) -> threading.Lock:
    key = (z, x, y)
    with _LOCKS_GUARD:
        lock = _TILE_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _TILE_LOCKS[key] = lock
        return lock


def _meta_path(png: Path) -> Path:
    return png.with_name(png.name + ".meta")


def _read_meta(png: Path) -> dict[str, Any]:
    path = _meta_path(png)
    if not path.is_file():
        if png.is_file():
            mtime = png.stat().st_mtime
            return {
                "etag": "",
                "last_modified": "",
                "fetched_at": mtime,
                "expires_at": mtime + MIN_CACHE_SECONDS,
            }
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _ttl_from_headers(headers: dict[str, str]) -> int:
    max_age = None
    cc = headers.get("cache-control") or ""
    for part in cc.split(","):
        part = part.strip().lower()
        if part.startswith("max-age="):
            raw = part.split("=", 1)[1].strip()
            try:
                max_age = max(0, int(raw))
            except ValueError:
                pass
    return max(MIN_CACHE_SECONDS, max_age or 0)


def _write_tile(png: Path, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
    png.parent.mkdir(parents=True, exist_ok=True)
    tmp = png.with_suffix(".png.tmp")
    tmp.write_bytes(body)
    tmp.replace(png)
    now = time.time()
    meta = {
        "etag": headers.get("etag") or "",
        "last_modified": headers.get("last-modified") or "",
        "fetched_at": now,
        "expires_at": now + _ttl_from_headers(headers),
    }
    meta_tmp = png.with_name(png.name + ".meta.tmp")
    meta_tmp.write_text(json.dumps(meta), encoding="utf-8")
    meta_tmp.replace(_meta_path(png))
    return meta


def _touch_meta(png: Path, meta: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    now = time.time()
    updated = dict(meta)
    if headers.get("etag"):
        updated["etag"] = headers["etag"]
    if headers.get("last-modified"):
        updated["last_modified"] = headers["last-modified"]
    updated["fetched_at"] = now
    updated["expires_at"] = now + _ttl_from_headers(headers)
    path = _meta_path(png)
    tmp = png.with_name(png.name + ".meta.tmp")
    tmp.write_text(json.dumps(updated), encoding="utf-8")
    tmp.replace(path)
    return updated


def _remaining(meta: dict[str, Any]) -> int:
    try:
        expires = float(meta.get("expires_at") or 0)
    except (TypeError, ValueError):
        expires = 0
    return max(0, int(expires - time.time()))


def _browser_max_age(meta: dict[str, Any], source: str) -> int:
    if source == "stale":
        return 60
    remaining = _remaining(meta)
    if remaining > 0:
        return remaining
    return MIN_CACHE_SECONDS


def _fetch(
    z: int,
    x: int,
    y: int,
    *,
    etag: str = "",
    last_modified: str = "",
    referer: str = "",
) -> tuple[int, bytes, dict[str, str]]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "image/png",
    }
    if referer:
        headers["Referer"] = referer
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    url = OSM_TILE_URL.format(z=z, x=x, y=y)
    req = urllib.request.Request(url, headers=headers)
    _FETCH_GATE.acquire()
    try:
        try:
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                body = resp.read()
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return int(resp.status), body, hdrs
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read() if exc.fp else b""
                hdrs = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
                return int(exc.code), body, hdrs
            finally:
                exc.close()
        except urllib.error.URLError as exc:
            raise TileError(f"OpenStreetMap unreachable: {exc.reason}") from exc
    finally:
        _FETCH_GATE.release()


def _get_tile_locked(
    cache_root: Path,
    z: int,
    x: int,
    y: int,
    *,
    referer: str,
) -> tuple[Path, str, int]:
    png = tile_path(cache_root, z, x, y)
    meta = _read_meta(png)
    fresh = png.is_file() and png.stat().st_size > 0 and _remaining(meta) > 0
    if fresh:
        return png, "hit", _browser_max_age(meta, "hit")

    etag = str(meta.get("etag") or "") if png.is_file() else ""
    last_modified = str(meta.get("last_modified") or "") if png.is_file() else ""
    try:
        status, body, headers = _fetch(
            z,
            x,
            y,
            etag=etag,
            last_modified=last_modified,
            referer=referer,
        )
    except TileError:
        if png.is_file() and png.stat().st_size > 0:
            return png, "stale", _browser_max_age(meta, "stale")
        raise

    if status == 304 and png.is_file():
        meta = _touch_meta(png, meta, headers)
        return png, "revalidate", _browser_max_age(meta, "revalidate")

    if status == 404:
        raise TileError("tile not found", status=404)

    if status != 200:
        if png.is_file() and png.stat().st_size > 0:
            return png, "stale", _browser_max_age(meta, "stale")
        raise TileError(f"OpenStreetMap HTTP {status}", status=502)

    if not body.startswith(PNG_MAGIC):
        if png.is_file() and png.stat().st_size > 0:
            return png, "stale", _browser_max_age(meta, "stale")
        raise TileError("OpenStreetMap returned a non-PNG tile", status=502)

    source = "revalidate" if png.is_file() else "miss"
    meta = _write_tile(png, body, headers)
    return png, source, _browser_max_age(meta, source)
