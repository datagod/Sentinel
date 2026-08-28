"""Push packet-cache TTL settings from Central to each sensor.

The sensor reads `central-cache.json` next to its packet.db (same SMB share
or local folder) and rebuilds its in-memory TTL cache.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from central.db import clamp_packet_cache_maxsize, clamp_packet_cache_ttl
from central.smb_fetch import SmbError, is_smb_path, write_smb_bytes

CACHE_FILENAME = "central-cache.json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def cache_settings_payload(client: dict[str, Any]) -> dict[str, Any]:
    return {
        "packet_cache_ttl_seconds": clamp_packet_cache_ttl(
            client.get("packet_cache_ttl_seconds")
        ),
        "packet_cache_maxsize": clamp_packet_cache_maxsize(
            client.get("packet_cache_maxsize")
        ),
        "updated_at": _now(),
    }


def _sidecar_url(packet_url: str, filename: str) -> str:
    parsed = urlparse(packet_url.strip())
    path = parsed.path.rstrip("/")
    parent = path.rsplit("/", 1)[0] if "/" in path else ""
    new_path = f"{parent}/{filename}" if parent else f"/{filename}"
    return urlunparse(parsed._replace(path=new_path))


def push_client_cache_settings(client: dict[str, Any]) -> tuple[bool, str]:
    """Write central-cache.json next to the client's packet.db. Returns (ok, message)."""
    raw = str(client.get("db_path") or "").strip()
    if not raw:
        return False, "client has no database path"
    payload = cache_settings_payload(client)
    body = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    try:
        if is_smb_path(raw):
            dest = _sidecar_url(raw, CACHE_FILENAME)
            write_smb_bytes(
                dest,
                body,
                username=client.get("smb_username") or None,
                password=client.get("smb_password") or None,
            )
            return True, dest
        path = Path(raw)
        dest = path.parent / CACHE_FILENAME
        dest.write_bytes(body)
        return True, str(dest)
    except (OSError, SmbError) as exc:
        return False, str(exc)
