"""Copy new Packet rows from client SQLite databases into the central store."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from central.db import (
    PACKET_COLUMNS,
    Store,
    apply_device_tags_to_packets,
    apply_friendly_to_packets,
    get_client,
    list_clients,
    log_activity,
)
from central.smb_fetch import SmbError, fetch_smb_database, is_smb_path

BATCH_SIZE = 500


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _open_client_db(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=8)
    conn.row_factory = sqlite3.Row
    return conn


def _select_columns(client_conn: sqlite3.Connection) -> list[str]:
    info = client_conn.execute("PRAGMA table_info(Packet)").fetchall()
    names = {row["name"] for row in info}
    if "id" not in names:
        raise RuntimeError("client Packet table has no id column")
    return ["id"] + [col for col in PACKET_COLUMNS if col in names]


def _resolve_client_db(client: dict[str, Any], cache_dir: Path) -> Path:
    raw = str(client.get("db_path") or "").strip()
    if is_smb_path(raw):
        return fetch_smb_database(
            raw,
            cache_dir,
            username=client.get("smb_username") or None,
            password=client.get("smb_password") or None,
        )
    path = Path(raw)
    if not path.is_file():
        raise FileNotFoundError(f"database not reachable: {path}")
    return path


def _smb_status(exc: SmbError) -> str:
    text = str(exc).lower()
    if any(token in text for token in ("access_denied", "logon", "auth", "password")):
        return "error"
    return "offline"


def ingest_client(store: Store, client_id: int) -> dict[str, Any]:
    started = _now()
    client = store.run(lambda conn: get_client(conn, client_id))
    if not client:
        return {
            "client_id": client_id,
            "status": "error",
            "rows_copied": 0,
            "message": "client not found",
        }

    cache_dir = store.path.parent / "smb-cache" / str(client_id)
    resolved: Path | None = None
    resolve_error: str | None = None
    resolve_status = "offline"
    try:
        resolved = _resolve_client_db(client, cache_dir)
    except FileNotFoundError as exc:
        resolve_error = str(exc)
        resolve_status = "offline"
    except SmbError as exc:
        resolve_error = str(exc)
        resolve_status = _smb_status(exc)

    def _run(conn: sqlite3.Connection) -> dict[str, Any]:
        if resolve_error or resolved is None:
            return _finish(
                conn,
                int(client["id"]),
                started,
                status=resolve_status,
                rows=0,
                message=resolve_error,
                last_source_id=int(client.get("last_source_id") or 0),
                last_capture_date=client.get("last_capture_date"),
            )
        return _ingest_one(conn, client, started, resolved)

    return store.run(_run)


def ingest_all(store: Store, *, enabled_only: bool = True) -> list[dict[str, Any]]:
    def _clients(conn: sqlite3.Connection) -> list[dict[str, Any]]:
        clients = list_clients(conn)
        if enabled_only:
            clients = [c for c in clients if c["enabled"]]
        return clients

    clients = store.run(_clients)
    return [ingest_client(store, int(c["id"])) for c in clients]


def _ingest_one(
    central: sqlite3.Connection,
    client: dict[str, Any],
    started: str,
    path: Path,
) -> dict[str, Any]:
    client_id = int(client["id"])
    last_source_id = int(client.get("last_source_id") or 0)

    if not path.is_file():
        return _finish(
            central,
            client_id,
            started,
            status="offline",
            rows=0,
            message=f"database not reachable: {path}",
            last_source_id=last_source_id,
            last_capture_date=client.get("last_capture_date"),
        )

    try:
        client_db = _open_client_db(path)
    except sqlite3.Error as exc:
        return _finish(
            central,
            client_id,
            started,
            status="error",
            rows=0,
            message=f"could not open client database: {exc}",
            last_source_id=last_source_id,
            last_capture_date=client.get("last_capture_date"),
        )

    try:
        columns = _select_columns(client_db)
        placeholders = ", ".join("?" for _ in columns[1:])  # skip id
        insert_sql = f"""
            INSERT OR IGNORE INTO Packet (client_id, source_id, {", ".join(columns[1:])})
            VALUES (?, ?, {placeholders})
        """
        before = central.execute(
            "SELECT COUNT(*) AS n FROM Packet WHERE client_id = ?",
            (client_id,),
        ).fetchone()["n"]
        max_id = last_source_id
        last_capture = client.get("last_capture_date")
        select_sql = (
            f"SELECT {', '.join(columns)} FROM Packet "
            "WHERE id > ? ORDER BY id"
        )
        rows = client_db.execute(select_sql, (last_source_id,))
        batch: list[tuple[Any, ...]] = []

        def _flush() -> None:
            if batch:
                central.executemany(insert_sql, batch)
                batch.clear()

        while True:
            row = rows.fetchone()
            if row is None:
                break
            source_id = int(row["id"])
            values = [client_id, source_id] + [row[col] for col in columns[1:]]
            batch.append(tuple(values))
            max_id = max(max_id, source_id)
            capture = row["CaptureDate"] if "CaptureDate" in row.keys() else None
            if capture:
                last_capture = str(capture)
            if len(batch) >= BATCH_SIZE:
                _flush()
        _flush()
        after = central.execute(
            "SELECT COUNT(*) AS n FROM Packet WHERE client_id = ?",
            (client_id,),
        ).fetchone()["n"]
        copied = int(after) - int(before)
        if copied:
            apply_friendly_to_packets(central)
            apply_device_tags_to_packets(central)
        return _finish(
            central,
            client_id,
            started,
            status="ok",
            rows=copied,
            message=None,
            last_source_id=max_id,
            last_capture_date=last_capture,
        )
    except sqlite3.Error as exc:
        central.rollback()
        return _finish(
            central,
            client_id,
            started,
            status="error",
            rows=0,
            message=str(exc),
            last_source_id=last_source_id,
            last_capture_date=client.get("last_capture_date"),
        )
    finally:
        client_db.close()


def _finish(
    central: sqlite3.Connection,
    client_id: int,
    started: str,
    *,
    status: str,
    rows: int,
    message: str | None,
    last_source_id: int,
    last_capture_date: str | None,
) -> dict[str, Any]:
    finished = _now()
    existing = central.execute(
        "SELECT last_success_at, last_status FROM IngestState WHERE client_id = ?",
        (client_id,),
    ).fetchone()
    success_at = finished if status == "ok" else (existing["last_success_at"] if existing else None)
    prev_status = existing["last_status"] if existing else None
    central.execute(
        """
        INSERT INTO IngestState (
            client_id, last_source_id, last_capture_date, last_success_at,
            last_error, last_rows, last_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(client_id) DO UPDATE SET
            last_source_id = excluded.last_source_id,
            last_capture_date = excluded.last_capture_date,
            last_success_at = excluded.last_success_at,
            last_error = excluded.last_error,
            last_rows = excluded.last_rows,
            last_status = excluded.last_status
        """,
        (
            client_id,
            last_source_id,
            last_capture_date,
            success_at,
            message,
            rows,
            status,
        ),
    )
    central.execute(
        """
        INSERT INTO IngestLog (client_id, started_at, finished_at, rows_copied, status, message)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (client_id, started, finished, rows, status, message),
    )
    name_row = central.execute(
        "SELECT name FROM Client WHERE id = ?", (client_id,)
    ).fetchone()
    name = name_row["name"] if name_row else f"client {client_id}"
    if status == "ok":
        if rows > 0:
            log_activity(
                central,
                f"{name}: copied {rows} new packet{'s' if rows != 1 else ''}",
                level="success",
                source="ingest",
                commit=False,
            )
    elif status == "offline":
        if prev_status != "offline":
            log_activity(
                central,
                f"{name}: offline — {message or 'database not reachable'}",
                level="warning",
                source="ingest",
                commit=False,
            )
    else:
        log_activity(
            central,
            f"{name}: {message or 'ingest failed'}",
            level="error",
            source="ingest",
            commit=False,
        )
    central.commit()
    return {
        "client_id": client_id,
        "status": status,
        "rows_copied": rows,
        "message": message,
        "last_source_id": last_source_id,
    }
