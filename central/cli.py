"""Sentinel Central CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import uvicorn

from central import __version__
from central.config import db_path, load_settings, seed_clients

from central.db import (
    Store,
    apply_friendly_to_packets,
    log_activity,
    seed_clients as seed_db_clients,
    upsert_devices,
)
from central.fing_import import SOURCE_FING, devices_from_fing
from central.ingest import ingest_all
from central.web.server import create_app


def _store(settings: dict) -> Store:
    store = Store(db_path(settings))
    seed_db_clients(store.conn, seed_clients(settings))
    return store


def cmd_ingest(settings: dict) -> int:
    store = _store(settings)
    try:
        results = ingest_all(store, enabled_only=True)
    finally:
        store.close()
    for result in results:
        print(json.dumps(result))
    if not results:
        print("No enabled clients configured.", file=sys.stderr)
        return 1
    errors = [r for r in results if r["status"] == "error"]
    return 1 if errors else 0


def cmd_import_fing(settings: dict, path: Path) -> int:
    if not path.is_file():
        print(f"File not found: {path}", file=sys.stderr)
        return 1
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        devices = devices_from_fing(payload)
    except Exception as exc:
        print(f"Could not parse Fing export: {exc}", file=sys.stderr)
        return 1
    store = _store(settings)
    try:
        result = store.run(lambda conn: upsert_devices(conn, devices))
        tagged = store.run(apply_friendly_to_packets)
        store.run(
            lambda conn: log_activity(
                conn,
                f"{SOURCE_FING}: {result['inserted']} new, {result['updated']} updated, "
                f"{tagged} packets tagged friendly",
                level="success",
                source="devices",
            )
        )
    finally:
        store.close()
    print(
        json.dumps(
            {**result, "packets_tagged": tagged, "source": SOURCE_FING},
            indent=2,
        )
    )
    return 0


def main() -> None:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--host", default=None)
    shared.add_argument("--port", type=int, default=None)
    parser = argparse.ArgumentParser(
        description="Sentinel Central — collect records from Sentinel clients",
        parents=[shared],
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="Start the management web server", parents=[shared])
    sub.add_parser("ingest", help="Pull new records from all enabled clients once")
    fing = sub.add_parser("import-fing", help="Import a Fing JSON device export as friendly devices")
    fing.add_argument("path", help="Path to Fing JSON export")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    settings = load_settings()
    command = args.command or "serve"

    if command == "ingest":
        raise SystemExit(cmd_ingest(settings))
    if command == "import-fing":
        raise SystemExit(cmd_import_fing(settings, Path(args.path)))

    host = args.host or str(settings.get("host", "127.0.0.1"))
    port = args.port or int(settings.get("port", 8093))
    app = create_app(settings)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
