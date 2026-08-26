"""Central SQLite store for aggregated Sentinel client records."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

T = TypeVar("T")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

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

SCHEMA = """
CREATE TABLE IF NOT EXISTS Client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    db_path TEXT NOT NULL,
    notes TEXT,
    smb_username TEXT,
    smb_password TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
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
    conn.commit()


def _ensure_column(conn: sqlite3.Connection, table: str, name: str, decl: str) -> None:
    cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if name not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


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
    inserted = 0
    for client in clients:
        existing = conn.execute(
            "SELECT id FROM Client WHERE name = ?", (client["name"],)
        ).fetchone()
        if existing:
            continue
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
               c.enabled, c.created_at,
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
               c.enabled, c.created_at,
               s.last_source_id, s.last_capture_date, s.last_success_at,
               s.last_error, s.last_rows, s.last_status
        FROM Client c
        LEFT JOIN IngestState s ON s.client_id = c.id
        WHERE c.id = ?
        """,
        (client_id,),
    ).fetchone()
    return dict(row) if row else None


def add_client(
    conn: sqlite3.Connection,
    name: str,
    db_path: str,
    notes: str = "",
    enabled: bool = True,
    smb_username: str = "",
    smb_password: str = "",
) -> dict[str, Any]:
    cur = conn.execute(
        """
        INSERT INTO Client (name, db_path, notes, smb_username, smb_password, enabled)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            name.strip(),
            db_path.strip(),
            notes.strip(),
            (smb_username or "").strip(),
            smb_password or "",
            1 if enabled else 0,
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
) -> dict[str, Any] | None:
    client = get_client(conn, client_id)
    if not client:
        return None
    conn.execute(
        """
        UPDATE Client
           SET name = ?, db_path = ?, notes = ?, enabled = ?,
               smb_username = ?, smb_password = ?
         WHERE id = ?
        """,
        (
            (name if name is not None else client["name"]).strip(),
            (db_path if db_path is not None else client["db_path"]).strip(),
            notes if notes is not None else (client["notes"] or ""),
            1 if (client["enabled"] if enabled is None else enabled) else 0,
            (smb_username if smb_username is not None else (client.get("smb_username") or "")).strip(),
            smb_password if smb_password is not None else (client.get("smb_password") or ""),
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
    return {
        "clients": clients,
        "enabled_clients": enabled,
        "packets": packets,
        "devices": devices,
        "friendly_devices": friendly,
        "last_ingest": last,
    }


def recent_packets(
    conn: sqlite3.Connection,
    *,
    limit: int = 100,
    offset: int = 0,
    query: str | None = None,
    client_id: int | None = None,
    tag: str | None = None,
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
    if client_id:
        sql += " AND p.client_id = ?"
        params.append(client_id)
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
    sql += " ORDER BY COALESCE(p.CaptureDate, p.ingested_at) DESC, p.id DESC LIMIT ? OFFSET ?"
    params.append(max(1, min(limit, 500)))
    params.append(max(0, int(offset)))
    rows = []
    for row in conn.execute(sql, params).fetchall():
        item = dict(row)
        item["tag_list"] = [t for t in str(item.get("tags") or "").split(", ") if t]
        rows.append(item)
    return rows


def list_devices(
    conn: sqlite3.Connection,
    *,
    query: str | None = None,
    friendly: bool | None = None,
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
    sql += " ORDER BY friendly DESC, last_seen DESC, name COLLATE NOCASE LIMIT ?"
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
