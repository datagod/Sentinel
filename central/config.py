"""Load Sentinel Central YAML config."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent


def _config_paths() -> list[Path]:
    return [
        ROOT / "config.yaml",
        Path.home() / ".config" / "sentinel-central" / "config.yaml",
    ]


def load_settings() -> dict[str, Any]:
    settings: dict[str, Any] = {}
    for path in _config_paths():
        if path.is_file():
            with path.open(encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if isinstance(loaded, dict):
                settings = loaded
                settings["_config_path"] = str(path)
            break
    return settings


def data_dir(settings: dict[str, Any] | None = None) -> Path:
    s = settings or load_settings()
    raw = str(s.get("data_dir", "data")).strip() or "data"
    path = Path(raw)
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path(settings: dict[str, Any] | None = None) -> Path:
    return data_dir(settings) / "sentinel-central.db"


def frigate_settings(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    s = settings or load_settings()
    raw = s.get("frigate") if isinstance(s.get("frigate"), dict) else {}
    cameras = raw.get("cameras") if isinstance(raw.get("cameras"), list) else []
    return {
        "base_url": str(raw.get("base_url") or "http://127.0.0.1:5000").rstrip("/"),
        "pad_seconds": max(5, min(int(raw.get("pad_seconds", 15)), 120)),
        "lead_seconds": max(0, min(int(raw.get("lead_seconds", 5)), 60)),
        "cameras": [str(c).strip() for c in cameras if str(c).strip()],
    }


def wigle_yaml(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    from central.wigle import wigle_defaults

    s = settings or load_settings()
    raw = s.get("wigle") if isinstance(s.get("wigle"), dict) else {}
    return wigle_defaults(raw)


def chatterbox_yaml(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    from central.chatterbox import chatterbox_defaults

    s = settings or load_settings()
    raw = s.get("chatterbox_tts") if isinstance(s.get("chatterbox_tts"), dict) else {}
    if not raw and isinstance(s.get("chatterbox"), dict):
        raw = s.get("chatterbox") or {}
    return chatterbox_defaults(raw)


def seed_clients(settings: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    s = settings or load_settings()
    raw = s.get("clients")
    if not isinstance(raw, list):
        return []
    clients: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        path = str(item.get("db_path") or "").strip()
        if not name or not path:
            continue
        clients.append(
            {
                "name": name,
                "db_path": path,
                "notes": str(item.get("notes") or "").strip(),
                "enabled": bool(item.get("enabled", True)),
            }
        )
    return clients
