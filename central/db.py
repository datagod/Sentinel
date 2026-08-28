"""Central SQLite store for aggregated Sentinel client records."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

T = TypeVar("T")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_ts(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    text = str(value).strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    if "." in text:
        text = text.split(".", 1)[0]
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def format_elapsed(start: Any, *, now: datetime | None = None) -> str:
    begin = _parse_ts(start)
    if not begin:
        return "—"
    current = now or datetime.now(timezone.utc).replace(tzinfo=None)
    seconds = int((current - begin).total_seconds())
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min"
    hours = minutes // 60
    mins = minutes % 60
    if hours < 48:
        return f"{hours}h {mins}m" if mins else f"{hours}h"
    days = hours // 24
    rem_h = hours % 24
    return f"{days}d {rem_h}h" if rem_h else f"{days}d"

PACKET_COLUMNS = (
    "CaptureDate",
    "FriendlyName",
    "FriendlyType",
    "PacketType",
    "DeviceType",
    "SourceMAC",
    "SourceVendor",
    "DestMAC",
    "DestVendor",
    "SSID",
    "Band",
    "Channel",
    "Latitude",
    "Longitude",
    "Signal",
)

DEVICE_TYPE_ALIASES = {
    "Mobile Phone (Probe Request)": "Mobile Phone",
}


def cleanse_device_type(value: Any) -> Any:
    """Normalize client-side device type labels stored on Packet rows."""
    if not isinstance(value, str):
        return value
    return DEVICE_TYPE_ALIASES.get(value.strip(), value)

SCHEMA = """
CREATE TABLE IF NOT EXISTS Client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    db_path TEXT NOT NULL,
    notes TEXT,
    smb_username TEXT,
    smb_password TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    packet_cache_ttl_seconds INTEGER NOT NULL DEFAULT 900,
    packet_cache_maxsize INTEGER NOT NULL DEFAULT 10000,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS IngestState (
    client_id INTEGER PRIMARY KEY,
    last_source_id INTEGER NOT NULL DEFAULT 0,
    last_capture_date TEXT,
    last_success_at TEXT,
    last_error TEXT,
    last_rows INTEGER NOT NULL DEFAULT 0,
    last_status TEXT,
    FOREIGN KEY (client_id) REFERENCES Client(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Packet (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    CaptureDate DATETIME,
    FriendlyName TEXT,
    FriendlyType TEXT,
    PacketType TEXT,
    DeviceType TEXT,
    SourceMAC TEXT,
    SourceVendor TEXT,
    DestMAC TEXT,
    DestVendor TEXT,
    SSID TEXT,
    Band TEXT,
    Channel TEXT,
    Latitude REAL,
    Longitude REAL,
    Signal INTEGER,
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (client_id, source_id),
    FOREIGN KEY (client_id) REFERENCES Client(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS IngestLog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    rows_copied INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    message TEXT,
    FOREIGN KEY (client_id) REFERENCES Client(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS ActivityLog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    source TEXT,
    message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Device (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL UNIQUE,
    name TEXT,
    device_type TEXT,
    vendor TEXT,
    model TEXT,
    os TEXT,
    hostname TEXT,
    ip_addresses TEXT,
    state TEXT,
    friendly INTEGER NOT NULL DEFAULT 0,
    tracked INTEGER NOT NULL DEFAULT 0,
    presence TEXT,
    last_signal INTEGER,
    arrived_at TEXT,
    departed_at TEXT,
    spoken_name TEXT,
    source TEXT,
    notes TEXT,
    first_seen TEXT,
    last_seen TEXT,
    imported_at TEXT,
    updated_at TEXT
);

CREATE INDEX IF NOT EXISTS i_packet_capturedate ON Packet(CaptureDate);
CREATE INDEX IF NOT EXISTS i_packet_sourcemac ON Packet(SourceMAC);
CREATE INDEX IF NOT EXISTS i_packet_client ON Packet(client_id);
CREATE INDEX IF NOT EXISTS i_ingestlog_started ON IngestLog(started_at);
CREATE INDEX IF NOT EXISTS i_activity_id ON ActivityLog(id);
CREATE INDEX IF NOT EXISTS i_device_mac ON Device(mac);
CREATE INDEX IF NOT EXISTS i_device_friendly ON Device(friendly);

CREATE TABLE IF NOT EXISTS Tag (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS PacketTag (
    packet_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    UNIQUE (packet_id, tag_id),
    FOREIGN KEY (packet_id) REFERENCES Packet(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES Tag(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS DeviceTag (
    mac TEXT NOT NULL,
    tag_id INTEGER NOT NULL,
    UNIQUE (mac, tag_id),
    FOREIGN KEY (tag_id) REFERENCES Tag(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS i_packettag_packet ON PacketTag(packet_id);
CREATE INDEX IF NOT EXISTS i_packettag_tag ON PacketTag(tag_id);
CREATE INDEX IF NOT EXISTS i_devicetag_mac ON DeviceTag(mac);

CREATE TABLE IF NOT EXISTS FrigateSetting (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    base_url TEXT NOT NULL,
    pad_seconds INTEGER NOT NULL DEFAULT 15,
    lead_seconds INTEGER NOT NULL DEFAULT 5,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS FrigateCamera (
    name TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    seen_at TEXT
);

CREATE TABLE IF NOT EXISTS WigleSetting (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    base_url TEXT NOT NULL,
    api_name TEXT,
    api_token TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS WigleCache (
    kind TEXT NOT NULL,
    query TEXT NOT NULL,
    payload TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (kind, query)
);

CREATE TABLE IF NOT EXISTS ChatterboxSetting (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 1,
    base_url TEXT NOT NULL,
    voice_mode TEXT NOT NULL DEFAULT 'clone',
    voice TEXT,
    output_format TEXT NOT NULL DEFAULT 'wav',
    timeout INTEGER NOT NULL DEFAULT 60,
    cooldown_seconds INTEGER NOT NULL DEFAULT 120,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS VoiceAlert (
    id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    template TEXT NOT NULL,
    min_packets INTEGER,
    window_minutes INTEGER,
    quiet_minutes INTEGER
);

CREATE TABLE IF NOT EXISTS VoiceAlertLog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    mac TEXT,
    text TEXT NOT NULL,
    audio_path TEXT,
    spoken_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS VoiceAlertQueue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    mac TEXT,
    text TEXT NOT NULL,
    audio_path TEXT,
    created_at TEXT NOT NULL,
    played INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS i_voicealertlog_key ON VoiceAlertLog(alert_id, mac, spoken_at);
CREATE INDEX IF NOT EXISTS i_voicealertqueue_played ON VoiceAlertQueue(played, id);

CREATE TABLE IF NOT EXISTS PresenceEvent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    event TEXT NOT NULL,
    at TEXT NOT NULL,
    signal INTEGER,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS i_presenceevent_mac ON PresenceEvent(mac, id);
"""


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    _ensure_column(conn, "Client", "smb_username", "TEXT")
    _ensure_column(conn, "Client", "smb_password", "TEXT")
    _ensure_column(conn, "Client", "packet_cache_ttl_seconds", "INTEGER NOT NULL DEFAULT 900")
    _ensure_column(conn, "Client", "packet_cache_maxsize", "INTEGER NOT NULL DEFAULT 10000")
    _ensure_column(conn, "VoiceAlert", "min_packets", "INTEGER")
    _ensure_column(conn, "VoiceAlert", "window_minutes", "INTEGER")
    _ensure_column(conn, "VoiceAlert", "quiet_minutes", "INTEGER")
    _ensure_column(conn, "Device", "tracked", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "Device", "presence", "TEXT")
    _ensure_column(conn, "Device", "last_signal", "INTEGER")
    _ensure_column(conn, "Device", "arrived_at", "TEXT")
    _ensure_column(conn, "Device", "departed_at", "TEXT")
    _ensure_column(conn, "Device", "spoken_name", "TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS i_device_tracked ON Device(tracked)")
    conn.execute("CREATE INDEX IF NOT EXISTS i_presenceevent_mac ON PresenceEvent(mac, id)")
    _cleanse_device_types(conn)
    _seed_voice_alerts(conn)
    conn.commit()


def _cleanse_device_types(conn: sqlite3.Connection) -> None:
    for old, new in DEVICE_TYPE_ALIASES.items():
        conn.execute("UPDATE Packet SET DeviceType = ? WHERE DeviceType = ?", (new, old))
        conn.execute("UPDATE Device SET device_type = ? WHERE device_type = ?", (new, old))


VOICE_ALERT_TYPES = (
    {
        "id": "new_phone",
        "label": "New Phone Detected",
        "template": "New phone detected.",
        "default": 1,
        "hint": "Spoken the first time a mobile phone MAC appears.",
    },
    {
        "id": "intruder",
        "label": "Intruder Alert",
        "template": "Intruder alert.",
        "default": 1,
        "hint": "Spoken when a non-friendly device meets the packet threshold below.",
        "min_packets": 5,
        "window_minutes": 5,
        "has_threshold": True,
    },
    {
        "id": "friendly",
        "label": "Friendly Device Detected",
        "template": "Friendly device {name} detected.",
        "default": 0,
        "hint": "Spoken when a friendly device is seen, using its name, only after it has been absent for the minutes below.",
        "quiet_minutes": 30,
        "has_quiet_period": True,
        "quiet_label": "Only announce if not seen for",
    },
    {
        "id": "left_premises",
        "label": "Left Premises",
        "template": "{name} has left the premises.",
        "default": 1,
        "hint": "Spoken when a tracked device has no packets for the minutes below. Turn on Track for a device on the Devices page.",
        "quiet_minutes": 15,
        "has_quiet_period": True,
        "quiet_label": "No packets for",
        "template_editable": True,
    },
    {
        "id": "entered_premises",
        "label": "Entered Premises",
        "template": "{name} has entered the premises.",
        "default": 1,
        "hint": "Spoken when a tracked device is seen again after being marked away. Uses the absence window on Left Premises.",
        "template_editable": True,
    },
    {
        "id": "new_device",
        "label": "New Device Detected",
        "template": "New device detected.",
        "default": 0,
        "hint": "Spoken the first time any other MAC appears.",
    },
)


def _ensure_column(conn: sqlite3.Connection, table: str, name: str, decl: str) -> None:
    cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if name not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def ensure_frigate_settings(
    conn: sqlite3.Connection,
    *,
    base_url: str,
    pad_seconds: int,
    lead_seconds: int,
    cameras: list[str] | None = None,
) -> None:
    existing = conn.execute("SELECT id FROM FrigateSetting WHERE id = 1").fetchone()
    if existing:
        return
    now = _now()
    conn.execute(
        """
        INSERT INTO FrigateSetting (id, base_url, pad_seconds, lead_seconds, updated_at)
        VALUES (1, ?, ?, ?, ?)
        """,
        (base_url, int(pad_seconds), int(lead_seconds), now),
    )
    for name in cameras or []:
        label = str(name).strip()
        if not label:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO FrigateCamera (name, enabled, seen_at) VALUES (?, 1, ?)",
            (label, now),
        )
    conn.commit()


def get_frigate_settings(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM FrigateSetting WHERE id = 1").fetchone()
    if not row:
        return None
    cameras = [
        {"name": r["name"], "enabled": bool(r["enabled"]), "seen_at": r["seen_at"]}
        for r in conn.execute(
            "SELECT name, enabled, seen_at FROM FrigateCamera ORDER BY name COLLATE NOCASE"
        )
    ]
    return {
        "base_url": row["base_url"],
        "pad_seconds": int(row["pad_seconds"]),
        "lead_seconds": int(row["lead_seconds"]),
        "updated_at": row["updated_at"],
        "cameras": cameras,
        "disabled_cameras": [c["name"] for c in cameras if not c["enabled"]],
    }


def save_frigate_settings(
    conn: sqlite3.Connection,
    *,
    base_url: str,
    pad_seconds: int,
    lead_seconds: int,
) -> dict[str, Any]:
    now = _now()
    conn.execute(
        """
        INSERT INTO FrigateSetting (id, base_url, pad_seconds, lead_seconds, updated_at)
        VALUES (1, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            base_url = excluded.base_url,
            pad_seconds = excluded.pad_seconds,
            lead_seconds = excluded.lead_seconds,
            updated_at = excluded.updated_at
        """,
        (base_url, int(pad_seconds), int(lead_seconds), now),
    )
    conn.commit()
    saved = get_frigate_settings(conn)
    if not saved:
        raise RuntimeError("Frigate settings were not saved")
    return saved


def upsert_frigate_cameras(
    conn: sqlite3.Connection, names: list[str]
) -> list[dict[str, Any]]:
    now = _now()
    live: list[str] = []
    for raw in names:
        name = str(raw).strip()
        if not name:
            continue
        live.append(name)
        conn.execute(
            """
            INSERT INTO FrigateCamera (name, enabled, seen_at)
            VALUES (?, 1, ?)
            ON CONFLICT(name) DO UPDATE SET seen_at = excluded.seen_at
            """,
            (name, now),
        )
    conn.commit()
    live_set = set(live)
    return [
        {
            "name": r["name"],
            "enabled": bool(r["enabled"]),
            "seen_at": r["seen_at"],
            "live": r["name"] in live_set,
        }
        for r in conn.execute(
            "SELECT name, enabled, seen_at FROM FrigateCamera ORDER BY name COLLATE NOCASE"
        )
    ]


def set_frigate_camera_enabled(
    conn: sqlite3.Connection, name: str, enabled: bool
) -> dict[str, Any]:
    label = str(name).strip()
    if not label:
        raise ValueError("camera name is required")
    now = _now()
    conn.execute(
        """
        INSERT INTO FrigateCamera (name, enabled, seen_at)
        VALUES (?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            enabled = excluded.enabled,
            seen_at = COALESCE(FrigateCamera.seen_at, excluded.seen_at)
        """,
        (label, 1 if enabled else 0, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT name, enabled, seen_at FROM FrigateCamera WHERE name = ?",
        (label,),
    ).fetchone()
    return {
        "name": row["name"],
        "enabled": bool(row["enabled"]),
        "seen_at": row["seen_at"],
    }


def ensure_wigle_settings(
    conn: sqlite3.Connection,
    *,
    enabled: bool = False,
    base_url: str = "https://api.wigle.net",
    api_name: str = "",
    api_token: str = "",
) -> None:
    existing = conn.execute("SELECT id FROM WigleSetting WHERE id = 1").fetchone()
    if existing:
        return
    conn.execute(
        """
        INSERT INTO WigleSetting (id, enabled, base_url, api_name, api_token, updated_at)
        VALUES (1, ?, ?, ?, ?, ?)
        """,
        (
            1 if enabled else 0,
            base_url,
            api_name,
            api_token,
            _now(),
        ),
    )
    conn.commit()


def get_wigle_settings(conn: sqlite3.Connection, *, include_secret: bool = False) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM WigleSetting WHERE id = 1").fetchone()
    if not row:
        return None
    token = row["api_token"] or ""
    data = {
        "enabled": bool(row["enabled"]),
        "base_url": row["base_url"] or "https://api.wigle.net",
        "api_name": row["api_name"] or "",
        "has_api_token": bool(token),
        "updated_at": row["updated_at"],
    }
    if include_secret:
        data["api_token"] = token
    return data


def save_wigle_settings(
    conn: sqlite3.Connection,
    *,
    enabled: bool,
    base_url: str,
    api_name: str,
    api_token: str | None = None,
) -> dict[str, Any]:
    existing = get_wigle_settings(conn, include_secret=True) or {}
    token = existing.get("api_token") or ""
    if api_token is not None:
        incoming = str(api_token).strip()
        if incoming:
            token = incoming
    now = _now()
    conn.execute(
        """
        INSERT INTO WigleSetting (id, enabled, base_url, api_name, api_token, updated_at)
        VALUES (1, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            enabled = excluded.enabled,
            base_url = excluded.base_url,
            api_name = excluded.api_name,
            api_token = excluded.api_token,
            updated_at = excluded.updated_at
        """,
        (
            1 if enabled else 0,
            base_url,
            api_name,
            token,
            now,
        ),
    )
    conn.commit()
    saved = get_wigle_settings(conn)
    if not saved:
        raise RuntimeError("WiGLE settings were not saved")
    return saved


def get_wigle_cache(
    conn: sqlite3.Connection, kind: str, query: str, *, max_age_hours: int = 168
) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT payload, fetched_at FROM WigleCache
         WHERE kind = ? AND query = ?
           AND datetime(fetched_at) >= datetime('now', ?)
        """,
        (kind, query, f"-{max(1, int(max_age_hours))} hours"),
    ).fetchone()
    if not row:
        return None
    try:
        data = json.loads(row["payload"])
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    data["cached"] = True
    data["fetched_at"] = row["fetched_at"]
    return data


def save_wigle_cache(
    conn: sqlite3.Connection, kind: str, query: str, payload: dict[str, Any]
) -> None:
    conn.execute(
        """
        INSERT INTO WigleCache (kind, query, payload, fetched_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(kind, query) DO UPDATE SET
            payload = excluded.payload,
            fetched_at = excluded.fetched_at
        """,
        (kind, query, json.dumps(payload), _now()),
    )
    conn.commit()


def _seed_voice_alerts(conn: sqlite3.Connection) -> None:
    for item in VOICE_ALERT_TYPES:
        conn.execute(
            """
            INSERT OR IGNORE INTO VoiceAlert
                (id, enabled, template, min_packets, window_minutes, quiet_minutes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                item["id"],
                int(item["default"]),
                item["template"],
                item.get("min_packets"),
                item.get("window_minutes"),
                item.get("quiet_minutes"),
            ),
        )
        if item.get("has_threshold"):
            conn.execute(
                """
                UPDATE VoiceAlert
                   SET min_packets = COALESCE(min_packets, ?),
                       window_minutes = COALESCE(window_minutes, ?)
                 WHERE id = ?
                """,
                (
                    int(item.get("min_packets") or 5),
                    int(item.get("window_minutes") or 5),
                    item["id"],
                ),
            )
        if item.get("has_quiet_period"):
            conn.execute(
                """
                UPDATE VoiceAlert
                   SET quiet_minutes = COALESCE(quiet_minutes, ?)
                 WHERE id = ?
                """,
                (int(item.get("quiet_minutes") or 30), item["id"]),
            )
        if item.get("template_editable"):
            conn.execute(
                """
                UPDATE VoiceAlert
                   SET template = COALESCE(NULLIF(template, ''), ?)
                 WHERE id = ?
                """,
                (item["template"], item["id"]),
            )


def ensure_chatterbox_settings(
    conn: sqlite3.Connection,
    *,
    enabled: bool,
    base_url: str,
    voice_mode: str,
    voice: str,
    output_format: str = "wav",
    timeout: int = 60,
    cooldown_seconds: int = 120,
) -> None:
    existing = conn.execute("SELECT id FROM ChatterboxSetting WHERE id = 1").fetchone()
    if existing:
        return
    conn.execute(
        """
        INSERT INTO ChatterboxSetting (
            id, enabled, base_url, voice_mode, voice, output_format,
            timeout, cooldown_seconds, updated_at
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            1 if enabled else 0,
            base_url,
            voice_mode,
            voice,
            output_format,
            int(timeout),
            int(cooldown_seconds),
            _now(),
        ),
    )
    conn.commit()


def get_chatterbox_settings(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM ChatterboxSetting WHERE id = 1").fetchone()
    if not row:
        return None
    alerts = []
    stored = {
        r["id"]: dict(r)
        for r in conn.execute(
            "SELECT id, enabled, template, min_packets, window_minutes, quiet_minutes FROM VoiceAlert"
        )
    }
    for item in VOICE_ALERT_TYPES:
        stored_alert = stored.get(item["id"]) or {}
        min_packets = stored_alert.get("min_packets")
        window_minutes = stored_alert.get("window_minutes")
        quiet_minutes = stored_alert.get("quiet_minutes")
        if item.get("has_threshold"):
            min_packets = int(min_packets or item.get("min_packets") or 5)
            window_minutes = int(window_minutes or item.get("window_minutes") or 5)
        if item.get("has_quiet_period"):
            quiet_minutes = int(quiet_minutes or item.get("quiet_minutes") or 30)
        alerts.append(
            {
                **item,
                "enabled": bool(stored_alert["enabled"]) if stored_alert else bool(item["default"]),
                "template": stored_alert.get("template") or item["template"],
                "min_packets": min_packets,
                "window_minutes": window_minutes,
                "quiet_minutes": quiet_minutes,
            }
        )
    voice_mode = row["voice_mode"] or "clone"
    voice = row["voice"] or ""
    return {
        "enabled": bool(row["enabled"]),
        "base_url": row["base_url"],
        "voice_mode": voice_mode,
        "voice": voice,
        "reference_audio_filename": voice if voice_mode == "clone" else "",
        "predefined_voice_id": voice if voice_mode == "predefined" else "",
        "output_format": row["output_format"] or "wav",
        "timeout": int(row["timeout"] or 60),
        "cooldown_seconds": int(row["cooldown_seconds"] or 120),
        "updated_at": row["updated_at"],
        "alerts": alerts,
    }


def save_chatterbox_settings(
    conn: sqlite3.Connection,
    *,
    enabled: bool,
    base_url: str,
    voice_mode: str,
    voice: str,
    output_format: str = "wav",
    timeout: int = 60,
    cooldown_seconds: int = 120,
) -> dict[str, Any]:
    now = _now()
    conn.execute(
        """
        INSERT INTO ChatterboxSetting (
            id, enabled, base_url, voice_mode, voice, output_format,
            timeout, cooldown_seconds, updated_at
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            enabled = excluded.enabled,
            base_url = excluded.base_url,
            voice_mode = excluded.voice_mode,
            voice = excluded.voice,
            output_format = excluded.output_format,
            timeout = excluded.timeout,
            cooldown_seconds = excluded.cooldown_seconds,
            updated_at = excluded.updated_at
        """,
        (
            1 if enabled else 0,
            base_url,
            voice_mode,
            voice,
            output_format,
            int(timeout),
            int(cooldown_seconds),
            now,
        ),
    )
    conn.commit()
    saved = get_chatterbox_settings(conn)
    if not saved:
        raise RuntimeError("Chatterbox settings were not saved")
    return saved


def _clamp_alert_threshold(value: Any, *, default: int, lo: int, hi: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(lo, min(parsed, hi))


def _sanitize_alert_template(value: Any, default: str) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return default
    if len(text) > 200:
        text = text[:200].rstrip()
    return text


def save_voice_alert(
    conn: sqlite3.Connection,
    alert_id: str,
    *,
    enabled: bool | None = None,
    min_packets: Any = None,
    window_minutes: Any = None,
    quiet_minutes: Any = None,
    template: Any = None,
) -> dict[str, Any]:
    known = {item["id"]: item for item in VOICE_ALERT_TYPES}
    spec = known.get(alert_id)
    if not spec:
        raise ValueError("unknown alert type")
    existing = conn.execute(
        """
        SELECT enabled, template, min_packets, window_minutes, quiet_minutes
          FROM VoiceAlert WHERE id = ?
        """,
        (alert_id,),
    ).fetchone()
    keep_enabled = bool(existing["enabled"]) if existing else bool(spec["default"])
    new_enabled = keep_enabled if enabled is None else bool(enabled)
    packets = existing["min_packets"] if existing else spec.get("min_packets")
    minutes = existing["window_minutes"] if existing else spec.get("window_minutes")
    quiet = existing["quiet_minutes"] if existing else spec.get("quiet_minutes")
    phrase = (existing["template"] if existing else None) or spec["template"]
    if spec.get("template_editable") and template is not None:
        phrase = _sanitize_alert_template(template, spec["template"])
    if spec.get("has_threshold"):
        if min_packets is not None:
            packets = _clamp_alert_threshold(min_packets, default=5, lo=1, hi=1000)
        else:
            packets = _clamp_alert_threshold(packets, default=5, lo=1, hi=1000)
        if window_minutes is not None:
            minutes = _clamp_alert_threshold(window_minutes, default=5, lo=1, hi=1440)
        else:
            minutes = _clamp_alert_threshold(minutes, default=5, lo=1, hi=1440)
    if spec.get("has_quiet_period"):
        quiet_default = int(spec.get("quiet_minutes") or 30)
        if quiet_minutes is not None:
            quiet = _clamp_alert_threshold(quiet_minutes, default=quiet_default, lo=1, hi=1440)
        else:
            quiet = _clamp_alert_threshold(quiet, default=quiet_default, lo=1, hi=1440)
    conn.execute(
        """
        INSERT INTO VoiceAlert
            (id, enabled, template, min_packets, window_minutes, quiet_minutes)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            enabled = excluded.enabled,
            template = excluded.template,
            min_packets = excluded.min_packets,
            window_minutes = excluded.window_minutes,
            quiet_minutes = excluded.quiet_minutes
        """,
        (alert_id, 1 if new_enabled else 0, phrase, packets, minutes, quiet),
    )
    conn.commit()
    row = conn.execute(
        """
        SELECT id, enabled, template, min_packets, window_minutes, quiet_minutes
          FROM VoiceAlert WHERE id = ?
        """,
        (alert_id,),
    ).fetchone()
    return {
        "id": row["id"],
        "enabled": bool(row["enabled"]),
        "template": row["template"],
        "min_packets": row["min_packets"],
        "window_minutes": row["window_minutes"],
        "quiet_minutes": row["quiet_minutes"],
    }


def set_voice_alert_enabled(
    conn: sqlite3.Connection, alert_id: str, enabled: bool
) -> dict[str, Any]:
    return save_voice_alert(conn, alert_id, enabled=enabled)


def _normalize_alert_phrase(text: str | None) -> str:
    return " ".join(str(text or "").strip().lower().split())


def voice_alert_on_cooldown(
    conn: sqlite3.Connection,
    alert_id: str,
    mac: str,
    cooldown_seconds: int,
    *,
    text: str | None = None,
) -> bool:
    """True if this device or this spoken phrase was already alerted inside the window."""
    window = max(15, int(cooldown_seconds))
    phrase = _normalize_alert_phrase(text)
    row = conn.execute(
        """
        SELECT spoken_at FROM VoiceAlertLog
         WHERE datetime(spoken_at) >= datetime('now', ?)
           AND (
                (alert_id = ? AND IFNULL(mac, '') = ?)
                OR (? != '' AND lower(trim(text)) = ?)
           )
         ORDER BY id DESC LIMIT 1
        """,
        (f"-{window} seconds", alert_id, mac or "", phrase, phrase),
    ).fetchone()
    return row is not None


def claim_voice_alert(
    conn: sqlite3.Connection,
    *,
    alert_id: str,
    mac: str | None,
    text: str,
) -> int:
    """Record the alert immediately so later candidates in this window honor cooldown."""
    now = _now()
    cur = conn.execute(
        """
        INSERT INTO VoiceAlertLog (alert_id, mac, text, audio_path, spoken_at)
        VALUES (?, ?, ?, NULL, ?)
        """,
        (alert_id, mac, text, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def enqueue_voice_alert(
    conn: sqlite3.Connection,
    *,
    alert_id: str,
    mac: str | None,
    text: str,
    audio_path: str | None,
    log_id: int | None = None,
) -> int:
    now = _now()
    if log_id:
        conn.execute(
            "UPDATE VoiceAlertLog SET audio_path = ? WHERE id = ?",
            (audio_path, log_id),
        )
    cur = conn.execute(
        """
        INSERT INTO VoiceAlertQueue (alert_id, mac, text, audio_path, created_at, played)
        VALUES (?, ?, ?, ?, ?, 0)
        """,
        (alert_id, mac, text, audio_path, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def record_voice_alert(
    conn: sqlite3.Connection,
    *,
    alert_id: str,
    mac: str | None,
    text: str,
    audio_path: str | None,
) -> int:
    log_id = claim_voice_alert(conn, alert_id=alert_id, mac=mac, text=text)
    return enqueue_voice_alert(
        conn,
        alert_id=alert_id,
        mac=mac,
        text=text,
        audio_path=audio_path,
        log_id=log_id,
    )


def list_pending_voice_alerts(conn: sqlite3.Connection, limit: int = 8) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT * FROM VoiceAlertQueue
         WHERE played = 0
         ORDER BY id
         LIMIT ?
        """,
        (max(1, min(limit, 20)),),
    ).fetchall()
    return [dict(r) for r in rows]


def mark_voice_alert_played(conn: sqlite3.Connection, queue_id: int) -> bool:
    cur = conn.execute(
        "UPDATE VoiceAlertQueue SET played = 1 WHERE id = ? AND played = 0",
        (queue_id,),
    )
    conn.commit()
    return cur.rowcount > 0


def get_voice_alert_queue_item(conn: sqlite3.Connection, queue_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM VoiceAlertQueue WHERE id = ?", (queue_id,)).fetchone()
    return dict(row) if row else None


class Store:
    """Thread-safe wrapper around the central database connection."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.conn = connect(path)
        init_db(self.conn)
        self._lock = threading.Lock()

    def run(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        with self._lock:
            return fn(self.conn)

    def close(self) -> None:
        with self._lock:
            self.conn.close()


def seed_clients(conn: sqlite3.Connection, clients: list[dict[str, Any]]) -> int:
    """Insert YAML clients only on first run (empty Client table).

    After that the database is the source of truth — deleting a client in the
    UI must not be undone on the next process start.
    """
    if not clients:
        return 0
    existing = conn.execute("SELECT COUNT(*) FROM Client").fetchone()[0]
    if existing:
        return 0
    inserted = 0
    for client in clients:
        conn.execute(
            """
            INSERT INTO Client (name, db_path, notes, smb_username, smb_password, enabled)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                client["name"],
                client["db_path"],
                client.get("notes") or "",
                client.get("smb_username") or "",
                client.get("smb_password") or "",
                1 if client.get("enabled", True) else 0,
            ),
        )
        inserted += 1
    if inserted:
        conn.commit()
    return inserted


def list_clients(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT c.id, c.name, c.db_path, c.notes, c.smb_username, c.smb_password,
               c.enabled, c.created_at, c.packet_cache_ttl_seconds, c.packet_cache_maxsize,
               s.last_source_id, s.last_capture_date, s.last_success_at,
               s.last_error, s.last_rows, s.last_status,
               (SELECT COUNT(*) FROM Packet p WHERE p.client_id = c.id) AS packet_count
        FROM Client c
        LEFT JOIN IngestState s ON s.client_id = c.id
        ORDER BY c.name COLLATE NOCASE
        """
    ).fetchall()
    return [dict(r) for r in rows]


def get_client(conn: sqlite3.Connection, client_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT c.id, c.name, c.db_path, c.notes, c.smb_username, c.smb_password,
               c.enabled, c.created_at, c.packet_cache_ttl_seconds, c.packet_cache_maxsize,
               s.last_source_id, s.last_capture_date, s.last_success_at,
               s.last_error, s.last_rows, s.last_status
        FROM Client c
        LEFT JOIN IngestState s ON s.client_id = c.id
        WHERE c.id = ?
        """,
        (client_id,),
    ).fetchone()
    return dict(row) if row else None


def clamp_packet_cache_ttl(value: Any) -> int:
    return _clamp_alert_threshold(value, default=900, lo=30, hi=86400)


def clamp_packet_cache_maxsize(value: Any) -> int:
    return _clamp_alert_threshold(value, default=10000, lo=100, hi=1000000)


def add_client(
    conn: sqlite3.Connection,
    name: str,
    db_path: str,
    notes: str = "",
    enabled: bool = True,
    smb_username: str = "",
    smb_password: str = "",
    packet_cache_ttl_seconds: Any = None,
    packet_cache_maxsize: Any = None,
) -> dict[str, Any]:
    cur = conn.execute(
        """
        INSERT INTO Client (
            name, db_path, notes, smb_username, smb_password, enabled,
            packet_cache_ttl_seconds, packet_cache_maxsize
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            name.strip(),
            db_path.strip(),
            notes.strip(),
            (smb_username or "").strip(),
            smb_password or "",
            1 if enabled else 0,
            clamp_packet_cache_ttl(packet_cache_ttl_seconds),
            clamp_packet_cache_maxsize(packet_cache_maxsize),
        ),
    )
    conn.commit()
    client = get_client(conn, int(cur.lastrowid))
    assert client is not None
    return client


def update_client(
    conn: sqlite3.Connection,
    client_id: int,
    *,
    name: str | None = None,
    db_path: str | None = None,
    notes: str | None = None,
    enabled: bool | None = None,
    smb_username: str | None = None,
    smb_password: str | None = None,
    packet_cache_ttl_seconds: Any = None,
    packet_cache_maxsize: Any = None,
) -> dict[str, Any] | None:
    client = get_client(conn, client_id)
    if not client:
        return None
    ttl = (
        clamp_packet_cache_ttl(packet_cache_ttl_seconds)
        if packet_cache_ttl_seconds is not None
        else clamp_packet_cache_ttl(client.get("packet_cache_ttl_seconds"))
    )
    maxsize = (
        clamp_packet_cache_maxsize(packet_cache_maxsize)
        if packet_cache_maxsize is not None
        else clamp_packet_cache_maxsize(client.get("packet_cache_maxsize"))
    )
    conn.execute(
        """
        UPDATE Client
           SET name = ?, db_path = ?, notes = ?, enabled = ?,
               smb_username = ?, smb_password = ?,
               packet_cache_ttl_seconds = ?, packet_cache_maxsize = ?
         WHERE id = ?
        """,
        (
            (name if name is not None else client["name"]).strip(),
            (db_path if db_path is not None else client["db_path"]).strip(),
            notes if notes is not None else (client["notes"] or ""),
            1 if (client["enabled"] if enabled is None else enabled) else 0,
            (smb_username if smb_username is not None else (client.get("smb_username") or "")).strip(),
            smb_password if smb_password is not None else (client.get("smb_password") or ""),
            ttl,
            maxsize,
            client_id,
        ),
    )
    conn.commit()
    return get_client(conn, client_id)


def public_client(client: dict[str, Any]) -> dict[str, Any]:
    data = dict(client)
    data["has_smb_password"] = bool(data.get("smb_password"))
    data.pop("smb_password", None)
    return data


def delete_client(conn: sqlite3.Connection, client_id: int) -> bool:
    cur = conn.execute("DELETE FROM Client WHERE id = ?", (client_id,))
    conn.commit()
    return cur.rowcount > 0


def log_activity(
    conn: sqlite3.Connection,
    message: str,
    *,
    level: str = "info",
    source: str = "server",
    commit: bool = True,
) -> None:
    conn.execute(
        "INSERT INTO ActivityLog (created_at, level, source, message) VALUES (?, ?, ?, ?)",
        (_now(), level, source, message),
    )
    if commit:
        conn.commit()


def list_activity(conn: sqlite3.Connection, limit: int = 80) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM ActivityLog ORDER BY id DESC LIMIT ?",
        (max(1, min(limit, 500)),),
    ).fetchall()
    return [dict(r) for r in rows]


def clear_activity(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM ActivityLog")
    conn.commit()


def dashboard_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    clients = conn.execute("SELECT COUNT(*) AS n FROM Client").fetchone()["n"]
    enabled = conn.execute(
        "SELECT COUNT(*) AS n FROM Client WHERE enabled = 1"
    ).fetchone()["n"]
    packets = conn.execute("SELECT COUNT(*) AS n FROM Packet").fetchone()["n"]
    devices = conn.execute(
        "SELECT COUNT(DISTINCT SourceMAC) AS n FROM Packet WHERE SourceMAC IS NOT NULL AND SourceMAC != ''"
    ).fetchone()["n"]
    friendly = conn.execute(
        "SELECT COUNT(*) AS n FROM Device WHERE friendly = 1"
    ).fetchone()["n"]
    last = conn.execute(
        "SELECT MAX(ingested_at) AS t FROM Packet"
    ).fetchone()["t"]
    latest_id = conn.execute("SELECT MAX(id) AS n FROM Packet").fetchone()["n"]
    tracked = conn.execute(
        "SELECT COUNT(*) AS n FROM Device WHERE tracked = 1"
    ).fetchone()["n"]
    tracked_inside = conn.execute(
        "SELECT COUNT(*) AS n FROM Device WHERE tracked = 1 AND presence = 'inside'"
    ).fetchone()["n"]
    latest_presence = conn.execute(
        "SELECT MAX(id) AS n FROM PresenceEvent"
    ).fetchone()["n"]
    return {
        "clients": clients,
        "enabled_clients": enabled,
        "packets": packets,
        "devices": devices,
        "friendly_devices": friendly,
        "tracked_devices": tracked,
        "tracked_inside": tracked_inside,
        "last_ingest": last,
        "latest_packet_id": int(latest_id or 0),
        "latest_presence_id": int(latest_presence or 0),
    }


PACKET_SORTS = {
    "captured": ("COALESCE(p.CaptureDate, p.ingested_at)", "desc"),
    "device": ("LOWER(COALESCE(device_name, p.FriendlyName, p.DeviceType, ''))", "asc"),
    "mac": ("p.SourceMAC", "asc"),
    "friendly": ("IFNULL(device_friendly, 0)", "desc"),
    "ssid": ("LOWER(IFNULL(p.SSID, ''))", "asc"),
    "type": ("LOWER(COALESCE(p.DeviceType, p.PacketType, ''))", "asc"),
    "signal": ("p.Signal", "desc"),
    "tags": ("LOWER(IFNULL(tags, ''))", "asc"),
}


def packet_sort_clause(sort: str | None, direction: str | None) -> tuple[str, str, str]:
    key = str(sort or "captured").strip().lower()
    if key not in PACKET_SORTS:
        key = "captured"
    expr, default_dir = PACKET_SORTS[key]
    way = str(direction or default_dir).strip().lower()
    if way not in ("asc", "desc"):
        way = default_dir
    extra = ""
    if key == "signal":
        extra = "(p.Signal IS NULL) ASC, "
    return key, way, f" ORDER BY {extra}{expr} {way.upper()}, p.id DESC"


def packet_filter_choices(conn: sqlite3.Connection) -> dict[str, list[str]]:
    def _distinct(column: str) -> list[str]:
        rows = conn.execute(
            f"""
            SELECT DISTINCT {column} AS v FROM Packet
             WHERE {column} IS NOT NULL AND TRIM({column}) != ''
             ORDER BY {column} COLLATE NOCASE
             LIMIT 200
            """
        ).fetchall()
        return [str(r["v"]) for r in rows if str(r["v"]).strip()]

    return {
        "device_types": _distinct("DeviceType"),
        "packet_types": _distinct("PacketType"),
        "bands": _distinct("Band"),
    }


def recent_packets(
    conn: sqlite3.Connection,
    *,
    limit: int = 100,
    offset: int = 0,
    query: str | None = None,
    client_id: int | None = None,
    tag: str | None = None,
    source_mac: str | None = None,
    after_id: int | None = None,
    friendly: bool | None = None,
    device_type: str | None = None,
    packet_type: str | None = None,
    band: str | None = None,
    ssid: str | None = None,
    signal_min: int | None = None,
    signal_max: int | None = None,
    hours: int | None = None,
    sort: str | None = None,
    sort_dir: str | None = None,
) -> list[dict[str, Any]]:
    sql = """
        SELECT p.*, c.name AS client_name,
               (SELECT GROUP_CONCAT(t.tag, ', ')
                  FROM PacketTag pt
                  JOIN Tag t ON t.id = pt.tag_id
                 WHERE pt.packet_id = p.id) AS tags,
               (SELECT d.friendly FROM Device d
                 WHERE d.mac = REPLACE(UPPER(p.SourceMAC), '-', ':')) AS device_friendly,
               (SELECT d.name FROM Device d
                 WHERE d.mac = REPLACE(UPPER(p.SourceMAC), '-', ':')) AS device_name
          FROM Packet p
          JOIN Client c ON c.id = p.client_id
         WHERE 1=1
    """
    params: list[Any] = []
    if after_id:
        sql += " AND p.id > ?"
        params.append(int(after_id))
    if client_id:
        sql += " AND p.client_id = ?"
        params.append(client_id)
    if source_mac:
        sql += f" AND {_mac_match_sql('p.SourceMAC')} = ?"
        params.append(_normalize_mac(source_mac))
    if tag:
        sql += """
          AND EXISTS (
                SELECT 1 FROM PacketTag pt
                JOIN Tag t ON t.id = pt.tag_id
               WHERE pt.packet_id = p.id AND t.tag = ?
          )
        """
        params.append(tag.strip().lower())
    if query:
        like = f"%{query}%"
        sql += """
          AND (
                p.SourceMAC LIKE ?
             OR p.DestMAC LIKE ?
             OR p.SSID LIKE ?
             OR p.SourceVendor LIKE ?
             OR p.FriendlyName LIKE ?
             OR p.DeviceType LIKE ?
             OR c.name LIKE ?
             OR EXISTS (
                    SELECT 1 FROM PacketTag pt
                    JOIN Tag t ON t.id = pt.tag_id
                   WHERE pt.packet_id = p.id AND t.tag LIKE ?
                )
          )
        """
        params.extend([like] * 8)
    if friendly is True:
        sql += f"""
          AND EXISTS (
                SELECT 1 FROM Device d
                 WHERE d.mac = {_mac_match_sql("p.SourceMAC")} AND d.friendly = 1
          )
        """
    elif friendly is False:
        sql += f"""
          AND NOT EXISTS (
                SELECT 1 FROM Device d
                 WHERE d.mac = {_mac_match_sql("p.SourceMAC")} AND d.friendly = 1
          )
        """
    if device_type:
        sql += " AND p.DeviceType = ?"
        params.append(device_type)
    if packet_type:
        sql += " AND p.PacketType = ?"
        params.append(packet_type)
    if band:
        sql += " AND p.Band = ?"
        params.append(band)
    if ssid:
        sql += " AND IFNULL(p.SSID, '') LIKE ?"
        params.append(f"%{ssid}%")
    if signal_min is not None:
        sql += " AND p.Signal IS NOT NULL AND p.Signal >= ?"
        params.append(int(signal_min))
    if signal_max is not None:
        sql += " AND p.Signal IS NOT NULL AND p.Signal <= ?"
        params.append(int(signal_max))
    if hours:
        sql += " AND datetime(p.CaptureDate) >= datetime('now', ?)"
        params.append(f"-{int(hours)} hours")
    _sort_key, _sort_dir, order_sql = packet_sort_clause(sort, sort_dir)
    sql += order_sql + " LIMIT ?"
    params.append(max(1, min(limit, 500)))
    if not after_id:
        sql += " OFFSET ?"
        params.append(max(0, int(offset)))
    rows = []
    for row in conn.execute(sql, params).fetchall():
        item = dict(row)
        item["tag_list"] = [t for t in str(item.get("tags") or "").split(", ") if t]
        rows.append(item)
    return rows


def get_packet(conn: sqlite3.Connection, packet_id: int) -> dict[str, Any] | None:
    sql = """
        SELECT p.*, c.name AS client_name,
               (SELECT GROUP_CONCAT(t.tag, ', ')
                  FROM PacketTag pt
                  JOIN Tag t ON t.id = pt.tag_id
                 WHERE pt.packet_id = p.id) AS tags,
               (SELECT d.friendly FROM Device d
                 WHERE d.mac = REPLACE(UPPER(p.SourceMAC), '-', ':')) AS device_friendly,
               (SELECT d.name FROM Device d
                 WHERE d.mac = REPLACE(UPPER(p.SourceMAC), '-', ':')) AS device_name
          FROM Packet p
          JOIN Client c ON c.id = p.client_id
         WHERE p.id = ?
    """
    row = conn.execute(sql, (packet_id,)).fetchone()
    if not row:
        return None
    item = dict(row)
    item["tag_list"] = [t for t in str(item.get("tags") or "").split(", ") if t]
    return item


def mac_stats(conn: sqlite3.Connection, mac: str) -> dict[str, Any]:
    mac_norm = _normalize_mac(mac)
    row = conn.execute(
        f"""
        SELECT
            COUNT(*) AS packets,
            MIN(p.CaptureDate) AS first_seen,
            MAX(p.CaptureDate) AS last_seen,
            MAX(p.Signal) AS strongest_signal,
            MIN(p.Signal) AS weakest_signal,
            MAX(p.SourceVendor) AS vendor,
            GROUP_CONCAT(DISTINCT NULLIF(p.SSID, '')) AS ssids,
            GROUP_CONCAT(DISTINCT p.PacketType) AS packet_types,
            GROUP_CONCAT(DISTINCT p.DeviceType) AS device_types,
            GROUP_CONCAT(DISTINCT p.Band) AS bands,
            GROUP_CONCAT(DISTINCT p.Channel) AS channels,
            GROUP_CONCAT(DISTINCT c.name) AS clients
        FROM Packet p
        JOIN Client c ON c.id = p.client_id
        WHERE {_mac_match_sql("p.SourceMAC")} = ?
        """,
        (mac_norm,),
    ).fetchone()
    data = dict(row) if row else {}
    tags = [
        r["tag"]
        for r in conn.execute(
            """
            SELECT t.tag FROM DeviceTag dt
            JOIN Tag t ON t.id = dt.tag_id
            WHERE dt.mac = ?
            ORDER BY t.tag COLLATE NOCASE
            """,
            (mac_norm,),
        ).fetchall()
    ]
    data["tag_list"] = tags
    data["mac"] = mac_norm
    return data


def list_devices(
    conn: sqlite3.Connection,
    *,
    query: str | None = None,
    friendly: bool | None = None,
    tracked: bool | None = None,
    tag: str | None = None,
    limit: int = 2000,
) -> list[dict[str, Any]]:
    sql = """
        WITH pkt AS (
            SELECT
                REPLACE(UPPER(p.SourceMAC), '-', ':') AS mac,
                MAX(p.SourceVendor) AS vendor,
                MAX(p.DeviceType) AS device_type,
                MAX(NULLIF(p.FriendlyName, '')) AS friendly_name,
                MIN(p.CaptureDate) AS first_seen,
                MAX(p.CaptureDate) AS last_seen,
                COUNT(*) AS packets,
                COUNT(DISTINCT p.client_id) AS client_count,
                GROUP_CONCAT(DISTINCT c.name) AS clients
            FROM Packet p
            JOIN Client c ON c.id = p.client_id
            WHERE p.SourceMAC IS NOT NULL AND p.SourceMAC != ''
            GROUP BY REPLACE(UPPER(p.SourceMAC), '-', ':')
        ),
        combined AS (
            SELECT
                COALESCE(d.mac, pkt.mac) AS mac,
                COALESCE(d.name, pkt.friendly_name) AS name,
                COALESCE(d.vendor, pkt.vendor) AS vendor,
                COALESCE(d.device_type, pkt.device_type) AS device_type,
                d.model,
                d.hostname,
                d.ip_addresses,
                COALESCE(pkt.first_seen, d.first_seen) AS first_seen,
                COALESCE(pkt.last_seen, d.last_seen) AS last_seen,
                COALESCE(pkt.packets, 0) AS packets,
                COALESCE(pkt.client_count, 0) AS client_count,
                pkt.clients,
                COALESCE(d.friendly, 0) AS friendly,
                COALESCE(d.tracked, 0) AS tracked,
                d.presence,
                d.last_signal,
                d.source,
                d.state
            FROM pkt
            LEFT JOIN Device d ON d.mac = pkt.mac
            UNION ALL
            SELECT
                d.mac,
                d.name,
                d.vendor,
                d.device_type,
                d.model,
                d.hostname,
                d.ip_addresses,
                d.first_seen,
                d.last_seen,
                0 AS packets,
                0 AS client_count,
                NULL AS clients,
                d.friendly,
                COALESCE(d.tracked, 0) AS tracked,
                d.presence,
                d.last_signal,
                d.source,
                d.state
            FROM Device d
            WHERE NOT EXISTS (SELECT 1 FROM pkt WHERE pkt.mac = d.mac)
        )
        SELECT c.*,
               (SELECT GROUP_CONCAT(t.tag, ', ')
                  FROM DeviceTag dt
                  JOIN Tag t ON t.id = dt.tag_id
                 WHERE dt.mac = c.mac) AS tags
          FROM combined c
         WHERE 1=1
    """
    params: list[Any] = []
    if friendly is True:
        sql += " AND friendly = 1"
    elif friendly is False:
        sql += " AND (friendly = 0 OR friendly IS NULL)"
    if tracked is True:
        sql += " AND tracked = 1"
    elif tracked is False:
        sql += " AND (tracked = 0 OR tracked IS NULL)"
    if tag:
        sql += """
          AND EXISTS (
                SELECT 1 FROM DeviceTag dt
                JOIN Tag t ON t.id = dt.tag_id
               WHERE dt.mac = c.mac AND t.tag = ?
          )
        """
        params.append(tag.strip().lower())
    if query:
        like = f"%{query}%"
        sql += """
          AND (
                mac LIKE ?
             OR IFNULL(name, '') LIKE ?
             OR IFNULL(vendor, '') LIKE ?
             OR IFNULL(device_type, '') LIKE ?
             OR IFNULL(hostname, '') LIKE ?
             OR IFNULL(ip_addresses, '') LIKE ?
             OR IFNULL(source, '') LIKE ?
             OR EXISTS (
                    SELECT 1 FROM DeviceTag dt
                    JOIN Tag t ON t.id = dt.tag_id
                   WHERE dt.mac = c.mac AND t.tag LIKE ?
                )
          )
        """
        params.extend([like] * 8)
    sql += " ORDER BY tracked DESC, friendly DESC, last_seen DESC, name COLLATE NOCASE LIMIT ?"
    params.append(max(1, min(limit, 5000)))
    rows = []
    for row in conn.execute(sql, params).fetchall():
        item = dict(row)
        item["tag_list"] = [t for t in str(item.get("tags") or "").split(", ") if t]
        rows.append(item)
    return rows


def suspicious_activity(
    conn: sqlite3.Connection,
    *,
    hours: int = 24,
    limit: int = 500,
) -> list[dict[str, Any]]:
    hours = max(1, min(int(hours), 168))
    rows = conn.execute(
        """
        SELECT
            REPLACE(UPPER(p.SourceMAC), '-', ':') AS mac,
            MAX(d.name) AS name,
            MAX(COALESCE(d.vendor, p.SourceVendor)) AS vendor,
            MAX(COALESCE(d.device_type, p.DeviceType)) AS device_type,
            GROUP_CONCAT(DISTINCT NULLIF(p.SSID, '')) AS ssids,
            GROUP_CONCAT(DISTINCT p.PacketType) AS packet_types,
            GROUP_CONCAT(DISTINCT c.name) AS clients,
            MIN(p.CaptureDate) AS first_seen,
            MAX(p.CaptureDate) AS last_seen,
            COUNT(*) AS packets,
            MAX(p.Signal) AS strongest_signal,
            MIN(p.Signal) AS weakest_signal,
            (SELECT GROUP_CONCAT(t.tag, ', ')
               FROM DeviceTag dt
               JOIN Tag t ON t.id = dt.tag_id
              WHERE dt.mac = REPLACE(UPPER(p.SourceMAC), '-', ':')) AS tags
        FROM Packet p
        JOIN Client c ON c.id = p.client_id
        LEFT JOIN Device d
          ON d.mac = REPLACE(UPPER(p.SourceMAC), '-', ':')
        WHERE p.SourceMAC IS NOT NULL AND p.SourceMAC != ''
          AND p.CaptureDate >= datetime('now', ?)
          AND (d.friendly IS NULL OR d.friendly = 0)
        GROUP BY REPLACE(UPPER(p.SourceMAC), '-', ':')
        ORDER BY last_seen DESC
        LIMIT ?
        """,
        (f"-{hours} hours", max(1, min(limit, 2000))),
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["tag_list"] = [t for t in str(item.get("tags") or "").split(", ") if t]
        item["ssid_list"] = [s for s in str(item.get("ssids") or "").split(",") if s]
        items.append(item)
    return items


def sensor_gps(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """Latest non-zero GPS reading from a connected sensor packet."""
    row = conn.execute(
        """
        SELECT p.Latitude AS lat, p.Longitude AS lon, p.CaptureDate AS captured_at,
               c.name AS client_name, p.client_id
          FROM Packet p
          JOIN Client c ON c.id = p.client_id
         WHERE p.Latitude IS NOT NULL AND p.Longitude IS NOT NULL
           AND ABS(p.Latitude) > 0.01 AND ABS(p.Longitude) > 0.01
         ORDER BY p.CaptureDate DESC
         LIMIT 1
        """
    ).fetchone()
    return dict(row) if row else None


def devices_for_map(
    conn: sqlite3.Connection,
    *,
    hours: int = 8,
    limit: int = 400,
) -> list[dict[str, Any]]:
    hours = max(1, min(int(hours), 168))
    rows = conn.execute(
        """
        SELECT
            REPLACE(UPPER(p.SourceMAC), '-', ':') AS mac,
            MAX(d.name) AS name,
            MAX(COALESCE(d.vendor, p.SourceVendor)) AS vendor,
            MAX(COALESCE(d.device_type, p.DeviceType)) AS device_type,
            MAX(IFNULL(d.friendly, 0)) AS friendly,
            MAX(NULLIF(p.FriendlyName, '')) AS packet_name,
            MAX(p.Signal) AS strongest_signal,
            MIN(p.Signal) AS weakest_signal,
            MAX(p.Band) AS band,
            MAX(p.CaptureDate) AS last_seen,
            COUNT(*) AS packets,
            GROUP_CONCAT(DISTINCT NULLIF(p.SSID, '')) AS ssids,
            (SELECT GROUP_CONCAT(t.tag, ', ')
               FROM DeviceTag dt
               JOIN Tag t ON t.id = dt.tag_id
              WHERE dt.mac = REPLACE(UPPER(p.SourceMAC), '-', ':')) AS tags
        FROM Packet p
        LEFT JOIN Device d
          ON d.mac = REPLACE(UPPER(p.SourceMAC), '-', ':')
        WHERE p.SourceMAC IS NOT NULL AND p.SourceMAC != ''
          AND p.CaptureDate >= datetime('now', ?)
          AND p.Signal IS NOT NULL
        GROUP BY REPLACE(UPPER(p.SourceMAC), '-', ':')
        ORDER BY last_seen DESC
        LIMIT ?
        """,
        (f"-{hours} hours", max(1, min(limit, 1000))),
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["tag_list"] = [t for t in str(item.get("tags") or "").split(", ") if t]
        item["ssid_list"] = [s for s in str(item.get("ssids") or "").split(",") if s]
        items.append(item)
    return items


def upsert_devices(conn: sqlite3.Connection, devices: list[dict[str, Any]]) -> dict[str, int]:
    inserted = 0
    updated = 0
    now = _now()
    for device in devices:
        mac = device.get("mac")
        if not mac:
            continue
        existing = conn.execute("SELECT id FROM Device WHERE mac = ?", (mac,)).fetchone()
        values = (
            device.get("name"),
            device.get("device_type"),
            device.get("vendor"),
            device.get("model"),
            device.get("os"),
            device.get("hostname"),
            device.get("ip_addresses"),
            device.get("state"),
            1 if device.get("friendly", True) else 0,
            device.get("source"),
            device.get("notes"),
            device.get("first_seen"),
            device.get("last_seen"),
            now,
            mac,
        )
        if existing:
            conn.execute(
                """
                UPDATE Device SET
                    name = ?, device_type = ?, vendor = ?, model = ?, os = ?,
                    hostname = ?, ip_addresses = ?, state = ?, friendly = ?,
                    source = ?, notes = ?, first_seen = COALESCE(?, first_seen),
                    last_seen = COALESCE(?, last_seen), updated_at = ?
                WHERE mac = ?
                """,
                values,
            )
            updated += 1
        else:
            conn.execute(
                """
                INSERT INTO Device (
                    name, device_type, vendor, model, os, hostname, ip_addresses,
                    state, friendly, source, notes, first_seen, last_seen,
                    imported_at, updated_at, mac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*values[:-2], now, now, mac),
            )
            inserted += 1
    conn.commit()
    return {"inserted": inserted, "updated": updated, "total": inserted + updated}


def get_device(conn: sqlite3.Connection, mac: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM Device WHERE mac = ?", (_normalize_mac(mac),)
    ).fetchone()
    return dict(row) if row else None


def set_friendly(
    conn: sqlite3.Connection,
    mac: str,
    friendly: bool,
    *,
    name: str | None = None,
    device_type: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    mac_norm = _normalize_mac(mac)
    now = _now()
    existing = get_device(conn, mac_norm) or {}
    keep_name = existing.get("name")
    keep_type = existing.get("device_type")
    new_name = str(name).strip() if name is not None else keep_name
    if new_name == "":
        new_name = keep_name
    new_type = str(device_type).strip() if device_type is not None else keep_type
    if new_type == "":
        new_type = keep_type
    new_source = existing.get("source") or source or "Manual"
    if existing:
        conn.execute(
            """
            UPDATE Device
               SET friendly = ?, name = ?, device_type = ?, updated_at = ?
             WHERE mac = ?
            """,
            (1 if friendly else 0, new_name, new_type, now, mac_norm),
        )
    else:
        conn.execute(
            """
            INSERT INTO Device (mac, name, device_type, friendly, source, imported_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (mac_norm, new_name, new_type, 1 if friendly else 0, new_source, now, now),
        )
    if friendly:
        if new_name:
            conn.execute(
                """
                UPDATE Packet
                   SET FriendlyName = ?, FriendlyType = ?
                 WHERE REPLACE(UPPER(SourceMAC), '-', ':') = ?
                """,
                (new_name, new_type, mac_norm),
            )
    else:
        conn.execute(
            """
            UPDATE Packet
               SET FriendlyName = NULL, FriendlyType = NULL
             WHERE REPLACE(UPPER(SourceMAC), '-', ':') = ?
            """,
            (mac_norm,),
        )
    conn.commit()
    device = get_device(conn, mac_norm)
    assert device is not None
    return device


def set_spoken_name(conn: sqlite3.Connection, mac: str, spoken_name: str | None) -> dict[str, Any]:
    mac_norm = _normalize_mac(mac)
    now = _now()
    phrase = " ".join(str(spoken_name or "").split())
    if len(phrase) > 200:
        phrase = phrase[:200].rstrip()
    existing = get_device(conn, mac_norm)
    if existing:
        conn.execute(
            "UPDATE Device SET spoken_name = ?, updated_at = ? WHERE mac = ?",
            (phrase or None, now, mac_norm),
        )
    else:
        conn.execute(
            """
            INSERT INTO Device (mac, spoken_name, friendly, source, imported_at, updated_at)
            VALUES (?, ?, 0, 'Manual', ?, ?)
            """,
            (mac_norm, phrase or None, now, now),
        )
    conn.commit()
    device = get_device(conn, mac_norm)
    assert device is not None
    return device


def presence_window_minutes(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT quiet_minutes FROM VoiceAlert WHERE id = 'left_premises'"
    ).fetchone()
    if row and row["quiet_minutes"] is not None:
        return _clamp_alert_threshold(row["quiet_minutes"], default=15, lo=1, hi=1440)
    return 15


def list_tracked_devices(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT mac, name, spoken_name, presence, last_signal, tracked, friendly, device_type,
               arrived_at, departed_at, vendor
          FROM Device
         WHERE tracked = 1
        """
    ).fetchall()
    return [dict(r) for r in rows]


def last_packet_snapshot(conn: sqlite3.Connection, mac: str) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT CaptureDate AS capture_date, Signal AS signal,
               NULLIF(FriendlyName, '') AS packet_name, DeviceType AS device_type,
               SourceVendor AS vendor
          FROM Packet
         WHERE REPLACE(UPPER(SourceMAC), '-', ':') = ?
         ORDER BY datetime(CaptureDate) DESC, id DESC
         LIMIT 1
        """,
        (_normalize_mac(mac),),
    ).fetchone()
    return dict(row) if row else {}


def update_device_presence(
    conn: sqlite3.Connection,
    mac: str,
    *,
    presence: str,
    last_signal: Any = None,
    arrived_at: Any = None,
    departed_at: Any = None,
    log_event: str | None = None,
    commit: bool = False,
) -> None:
    mac_norm = _normalize_mac(mac)
    now = _now()
    sets = [
        "presence = ?",
        "last_signal = COALESCE(?, last_signal)",
        "updated_at = ?",
    ]
    params: list[Any] = [presence, last_signal, now]
    if log_event == "entered":
        sets.append("arrived_at = ?")
        sets.append("departed_at = NULL")
        params.append(str(arrived_at or now))
    elif log_event == "left":
        sets.append("departed_at = ?")
        params.append(str(departed_at or now))
    else:
        if presence == "inside" and arrived_at:
            sets.append("arrived_at = COALESCE(arrived_at, ?)")
            params.append(str(arrived_at))
        if presence == "away" and departed_at:
            sets.append("departed_at = COALESCE(departed_at, ?)")
            params.append(str(departed_at))
    params.append(mac_norm)
    conn.execute(
        f"UPDATE Device SET {', '.join(sets)} WHERE mac = ?",
        params,
    )
    if log_event in ("entered", "left"):
        at = arrived_at if log_event == "entered" else departed_at
        conn.execute(
            """
            INSERT INTO PresenceEvent (mac, event, at, signal, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (mac_norm, log_event, str(at or now), last_signal, now),
        )
    if commit:
        conn.commit()


def set_tracked(conn: sqlite3.Connection, mac: str, tracked: bool) -> dict[str, Any]:
    mac_norm = _normalize_mac(mac)
    now = _now()
    existing = get_device(conn, mac_norm) or {}
    snap = last_packet_snapshot(conn, mac_norm)
    if not existing:
        conn.execute(
            """
            INSERT INTO Device (
                mac, name, device_type, vendor, friendly, tracked, source,
                imported_at, updated_at
            ) VALUES (?, ?, ?, ?, 0, ?, 'Manual', ?, ?)
            """,
            (
                mac_norm,
                snap.get("packet_name"),
                snap.get("device_type"),
                snap.get("vendor"),
                1 if tracked else 0,
                now,
                now,
            ),
        )
    else:
        conn.execute(
            "UPDATE Device SET tracked = ?, updated_at = ? WHERE mac = ?",
            (1 if tracked else 0, now, mac_norm),
        )
    if tracked:
        minutes = presence_window_minutes(conn)
        capture = snap.get("capture_date")
        last_dt = _parse_ts(capture)
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        seen_recently = bool(last_dt and now_dt - last_dt < timedelta(minutes=minutes))
        presence = "inside" if seen_recently else "away"
        if presence == "inside":
            conn.execute(
                """
                UPDATE Device
                   SET presence = ?, last_signal = COALESCE(?, last_signal),
                       arrived_at = COALESCE(arrived_at, ?), departed_at = NULL,
                       updated_at = ?
                 WHERE mac = ?
                """,
                (presence, snap.get("signal"), capture or now, now, mac_norm),
            )
        else:
            conn.execute(
                """
                UPDATE Device
                   SET presence = ?, last_signal = COALESCE(?, last_signal),
                       departed_at = COALESCE(departed_at, ?), updated_at = ?
                 WHERE mac = ?
                """,
                (presence, snap.get("signal"), capture or now, now, mac_norm),
            )
    else:
        conn.execute(
            "UPDATE Device SET presence = NULL, updated_at = ? WHERE mac = ?",
            (now, mac_norm),
        )
    conn.commit()
    device = get_device(conn, mac_norm)
    assert device is not None
    return device


def tracked_presence_report(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT
            d.mac,
            d.name,
            d.vendor,
            d.device_type,
            d.friendly,
            d.presence,
            d.arrived_at,
            d.departed_at,
            d.last_signal,
            (
                SELECT MAX(p.CaptureDate)
                  FROM Packet p
                 WHERE REPLACE(UPPER(p.SourceMAC), '-', ':') = d.mac
            ) AS last_seen,
            (
                SELECT COUNT(*) FROM PresenceEvent e
                 WHERE e.mac = d.mac AND e.event = 'entered'
            ) AS visits
          FROM Device d
         WHERE d.tracked = 1
         ORDER BY CASE d.presence WHEN 'inside' THEN 0 ELSE 1 END,
                  d.name COLLATE NOCASE,
                  d.mac
        """
    ).fetchall()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    items: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        inside = item.get("presence") == "inside"
        item["on_site"] = inside
        item["status"] = "on site" if inside else "away"
        if inside:
            item["duration_label"] = format_elapsed(item.get("arrived_at"), now=now)
            item["duration_kind"] = "on site"
        else:
            item["duration_label"] = format_elapsed(item.get("departed_at"), now=now)
            item["duration_kind"] = "away"
        items.append(item)
    return items


def apply_friendly_to_packets(conn: sqlite3.Connection) -> int:
    conn.execute(
        """
        UPDATE Packet
           SET FriendlyName = (
                    SELECT d.name FROM Device d
                     WHERE d.mac = REPLACE(UPPER(Packet.SourceMAC), '-', ':')
                       AND d.friendly = 1
               ),
               FriendlyType = (
                    SELECT d.device_type FROM Device d
                     WHERE d.mac = REPLACE(UPPER(Packet.SourceMAC), '-', ':')
                       AND d.friendly = 1
               )
         WHERE EXISTS (
                SELECT 1 FROM Device d
                 WHERE d.mac = REPLACE(UPPER(Packet.SourceMAC), '-', ':')
                   AND d.friendly = 1
               )
           AND (FriendlyName IS NULL OR FriendlyName = '')
        """
    )
    changed = conn.execute("SELECT changes() AS n").fetchone()["n"]
    conn.commit()
    return int(changed)


def _mac_match_sql(column: str) -> str:
    return f"REPLACE(UPPER({column}), '-', ':')"


def _normalize_mac(mac: str) -> str:
    hexpart = "".join(ch for ch in mac.upper() if ch in "0123456789ABCDEF")
    if len(hexpart) == 12:
        return ":".join(hexpart[i : i + 2] for i in range(0, 12, 2))
    return mac.strip().upper()


def _get_or_create_tag(conn: sqlite3.Connection, tag: str) -> int:
    label = tag.strip().lower()
    if not label:
        raise ValueError("tag is required")
    row = conn.execute("SELECT id FROM Tag WHERE tag = ?", (label,)).fetchone()
    if row:
        return int(row["id"])
    cur = conn.execute("INSERT INTO Tag (tag) VALUES (?)", (label,))
    return int(cur.lastrowid)


def list_tags(conn: sqlite3.Connection) -> list[str]:
    return [r["tag"] for r in conn.execute("SELECT tag FROM Tag ORDER BY tag COLLATE NOCASE")]


def add_tag_for_mac(conn: sqlite3.Connection, mac: str, tag: str) -> dict[str, Any]:
    mac_norm = _normalize_mac(mac)
    tag_id = _get_or_create_tag(conn, tag)
    conn.execute(
        "INSERT OR IGNORE INTO DeviceTag (mac, tag_id) VALUES (?, ?)",
        (mac_norm, tag_id),
    )
    conn.execute(
        f"""
        INSERT OR IGNORE INTO PacketTag (packet_id, tag_id)
        SELECT p.id, ?
          FROM Packet p
         WHERE {_mac_match_sql("p.SourceMAC")} = ?
        """,
        (tag_id, mac_norm),
    )
    packets = conn.execute("SELECT changes() AS n").fetchone()["n"]
    conn.commit()
    return {
        "mac": mac_norm,
        "tag": tag.strip().lower(),
        "packets_tagged": int(packets),
    }


def remove_tag_for_mac(conn: sqlite3.Connection, mac: str, tag: str) -> dict[str, Any]:
    mac_norm = _normalize_mac(mac)
    label = tag.strip().lower()
    row = conn.execute("SELECT id FROM Tag WHERE tag = ?", (label,)).fetchone()
    if not row:
        return {"mac": mac_norm, "tag": label, "removed": 0}
    tag_id = int(row["id"])
    conn.execute("DELETE FROM DeviceTag WHERE mac = ? AND tag_id = ?", (mac_norm, tag_id))
    conn.execute(
        f"""
        DELETE FROM PacketTag
         WHERE tag_id = ?
           AND packet_id IN (
                SELECT p.id FROM Packet p
                 WHERE {_mac_match_sql("p.SourceMAC")} = ?
           )
        """,
        (tag_id, mac_norm),
    )
    removed = conn.execute("SELECT changes() AS n").fetchone()["n"]
    leftover = conn.execute(
        "SELECT 1 FROM PacketTag WHERE tag_id = ? UNION SELECT 1 FROM DeviceTag WHERE tag_id = ?",
        (tag_id, tag_id),
    ).fetchone()
    if not leftover:
        conn.execute("DELETE FROM Tag WHERE id = ?", (tag_id,))
    conn.commit()
    return {"mac": mac_norm, "tag": label, "removed": int(removed)}


def apply_device_tags_to_packets(conn: sqlite3.Connection) -> int:
    conn.execute(
        f"""
        INSERT OR IGNORE INTO PacketTag (packet_id, tag_id)
        SELECT p.id, dt.tag_id
          FROM Packet p
          JOIN DeviceTag dt
            ON dt.mac = {_mac_match_sql("p.SourceMAC")}
        """
    )
    changed = conn.execute("SELECT changes() AS n").fetchone()["n"]
    conn.commit()
    return int(changed)


def recent_ingest_log(conn: sqlite3.Connection, limit: int = 25) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT l.*, c.name AS client_name
          FROM IngestLog l
          LEFT JOIN Client c ON c.id = l.client_id
         ORDER BY l.id DESC
         LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
