"""FastAPI web server for Sentinel Central."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.staticfiles import StaticFiles

from central import __version__
from central.config import db_path, data_dir, frigate_settings, seed_clients
from central.frigate import (
    FrigateError,
    clip_iter,
    event_bytes,
    event_clip_iter,
    lookup as frigate_lookup,
    nearest_event as frigate_nearest_event,
    snapshot_bytes,
)
from central.db import (
    Store,
    add_client,
    add_tag_for_mac,
    apply_friendly_to_packets,
    clear_activity,
    dashboard_stats,
    delete_client,
    get_client,
    list_activity,
    list_clients,
    list_devices,
    list_tags,
    log_activity,
    public_client,
    recent_packets,
    seed_clients as seed_db_clients,
    suspicious_activity,
    remove_tag_for_mac,
    set_friendly,
    update_client,
    upsert_devices,
)
from central.fing_import import SOURCE_FING, devices_from_fing
from central.ingest import ingest_all, ingest_client

WEB_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(WEB_DIR / "templates"))

_DT_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
)


def format_local_time(value: Any) -> str:
    """Render a UTC datetime or Unix timestamp in the server's local timezone."""
    if value is None or value == "":
        return "—"
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        n = float(value)
        if n > 1e12:
            n = n / 1000.0
        return datetime.fromtimestamp(n, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    text = str(value).strip()
    if not text:
        return "—"
    parsed = None
    for fmt in _DT_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            break
        except ValueError:
            continue
    if parsed is None:
        try:
            n = float(text)
            if n > 1e12:
                n = n / 1000.0
            return datetime.fromtimestamp(n, tz=timezone.utc).astimezone().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except (TypeError, ValueError, OSError, OverflowError):
            return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def to_unix_ts(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(int(value))
    text = str(value).strip()
    parsed = None
    for fmt in _DT_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            break
        except ValueError:
            continue
    if parsed is None:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return str(int(parsed.timestamp()))


TEMPLATES.env.filters["localtime"] = format_local_time
TEMPLATES.env.filters["unix"] = to_unix_ts


class AppState:
    def __init__(self, settings: dict[str, Any]) -> None:
        self.settings = settings
        self.store = Store(db_path(settings))
        seed_db_clients(self.store.conn, seed_clients(settings))
        self._task: asyncio.Task[None] | None = None

    @property
    def interval(self) -> int:
        return max(15, int(self.settings.get("ingest_interval_seconds", 60)))


def _nav(page: str, state: AppState) -> dict[str, Any]:
    stats = state.store.run(dashboard_stats)
    return {
        "page": page,
        "version": __version__,
        "stats": stats,
        "interval": state.interval,
        "log": state.store.run(lambda c: list_activity(c, 80)),
    }


def _public_clients(state: AppState) -> list[dict[str, Any]]:
    return [public_client(c) for c in state.store.run(list_clients)]


def create_app(settings: dict[str, Any]) -> FastAPI:
    state = AppState(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async def _loop() -> None:
            while True:
                try:
                    await asyncio.to_thread(ingest_all, state.store)
                except Exception:
                    pass
                await asyncio.sleep(state.interval)

        state._task = asyncio.create_task(_loop())
        yield
        if state._task:
            state._task.cancel()
        state.store.close()

    app = FastAPI(title="Sentinel Central", version=__version__, lifespan=lifespan)
    app.state.core = state

    static_dir = WEB_DIR / "static"
    icon_path = static_dir / "img" / "sentinel-central-icon.svg"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        if icon_path.is_file():
            return FileResponse(icon_path, media_type="image/svg+xml")
        return Response(status_code=404)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        clients = _public_clients(state)
        packets = state.store.run(lambda c: recent_packets(c, limit=40))
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {
                **_nav("dashboard", state),
                "clients": clients,
                "packets": packets,
            },
        )

    @app.get("/clients", response_class=HTMLResponse)
    async def clients_page(request: Request):
        return TEMPLATES.TemplateResponse(
            request,
            "clients.html",
            {**_nav("clients", state), "clients": _public_clients(state)},
        )

    @app.get("/packets", response_class=HTMLResponse)
    async def packets_page(
        request: Request,
        q: str = "",
        client_id: int | None = None,
        tag: str = "",
        limit: int = 200,
    ):
        page_size = max(1, min(limit, 200))
        packets = state.store.run(
            lambda c: recent_packets(
                c,
                limit=page_size,
                query=q.strip() or None,
                client_id=client_id,
                tag=tag.strip() or None,
            )
        )
        return TEMPLATES.TemplateResponse(
            request,
            "packets.html",
            {
                **_nav("packets", state),
                "packets": packets,
                "q": q,
                "client_id": client_id,
                "tag": tag,
                "page_size": page_size,
                "has_more": len(packets) == page_size,
                "clients": _public_clients(state),
                "tags": state.store.run(list_tags),
            },
        )

    @app.get("/devices", response_class=HTMLResponse)
    async def devices_page(
        request: Request,
        q: str = "",
        friendly: str = "",
        tag: str = "",
    ):
        flag = {"1": True, "0": False, "yes": True, "no": False}.get(friendly.lower(), None)
        devices = state.store.run(
            lambda c: list_devices(
                c,
                query=q.strip() or None,
                friendly=flag,
                tag=tag.strip() or None,
            )
        )
        return TEMPLATES.TemplateResponse(
            request,
            "devices.html",
            {
                **_nav("devices", state),
                "devices": devices,
                "q": q,
                "friendly": friendly,
                "tag": tag,
                "tags": state.store.run(list_tags),
            },
        )

    @app.get("/reports", response_class=HTMLResponse)
    async def reports_page(request: Request, hours: int = 24):
        hours = max(1, min(hours, 168))
        rows = state.store.run(lambda c: suspicious_activity(c, hours=hours))
        return TEMPLATES.TemplateResponse(
            request,
            "reports.html",
            {
                **_nav("reports", state),
                "hours": hours,
                "hour_choices": (1, 2, 6, 12, 24, 48, 72, 168),
                "rows": rows,
            },
        )

    @app.get("/frigate-media", response_class=HTMLResponse)
    async def frigate_media_page(
        request: Request,
        ts: float,
        mac: str = "",
        from_ts: float | None = None,
        nearest_delta: float | None = None,
        nearest_dir: str = "",
    ):
        fg = frigate_settings(state.settings)
        error = None
        try:
            data = await asyncio.to_thread(
                frigate_lookup,
                fg["base_url"],
                ts,
                fg["pad_seconds"],
                fg["cameras"] or None,
                fg["lead_seconds"],
            )
        except FrigateError as exc:
            data = {
                "cameras": [],
                "events": [],
                "reviews": [],
                "detection_cameras": [],
                "other_cameras": [],
                "ts": ts,
                "start": ts,
                "end": ts,
                "pad_seconds": fg["pad_seconds"],
                "lead_seconds": fg["lead_seconds"],
            }
            error = str(exc)
        when = datetime.fromtimestamp(ts, tz=timezone.utc)
        from_local = (
            format_local_time(datetime.fromtimestamp(from_ts, tz=timezone.utc))
            if from_ts
            else ""
        )
        return TEMPLATES.TemplateResponse(
            request,
            "frigate_media.html",
            {
                "version": __version__,
                "mac": mac,
                "local_ts": format_local_time(when),
                "error": error,
                "from_ts": from_ts,
                "from_local": from_local,
                "nearest_delta": nearest_delta,
                "nearest_dir": nearest_dir,
                **data,
                "packet_ts": ts,
            },
        )

    @app.get("/api/frigate/nearest")
    async def frigate_nearest(ts: float):
        fg = frigate_settings(state.settings)
        try:
            found = await asyncio.to_thread(frigate_nearest_event, fg["base_url"], ts)
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)
        if not found:
            return JSONResponse({"error": "No Frigate detections found."}, status_code=404)
        return JSONResponse(found)

    @app.get("/api/frigate/snapshot/{camera}")
    async def frigate_snapshot(camera: str, ts: float):
        fg = frigate_settings(state.settings)
        try:
            body, ctype = await asyncio.to_thread(
                snapshot_bytes, fg["base_url"], camera, ts
            )
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        return Response(content=body, media_type=ctype)

    @app.get("/api/frigate/event/{event_id}/snapshot.jpg")
    async def frigate_event_snapshot(event_id: str):
        fg = frigate_settings(state.settings)
        try:
            body, ctype = await asyncio.to_thread(
                event_bytes, fg["base_url"], event_id, "snapshot.jpg"
            )
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        return Response(content=body, media_type=ctype)

    @app.get("/api/frigate/event/{event_id}/thumbnail.jpg")
    async def frigate_event_thumbnail(event_id: str):
        fg = frigate_settings(state.settings)
        try:
            body, ctype = await asyncio.to_thread(
                event_bytes, fg["base_url"], event_id, "thumbnail.jpg"
            )
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        return Response(content=body, media_type=ctype)

    @app.get("/api/frigate/event/{event_id}/clip.mp4")
    async def frigate_event_clip(event_id: str):
        fg = frigate_settings(state.settings)
        try:
            iterator = event_clip_iter(fg["base_url"], event_id)
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        return StreamingResponse(iterator, media_type="video/mp4")

    @app.get("/api/frigate/clip/{camera}")
    async def frigate_clip(camera: str, start: float, end: float):
        fg = frigate_settings(state.settings)
        try:
            iterator = clip_iter(fg["base_url"], camera, start, end)
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        return StreamingResponse(iterator, media_type="video/mp4")

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        return TEMPLATES.TemplateResponse(
            request,
            "settings.html",
            {
                **_nav("settings", state),
                "settings": state.settings,
                "data_dir": str(data_dir(state.settings)),
                "db_path": str(db_path(state.settings)),
                "config_path": state.settings.get("_config_path", ""),
            },
        )

    @app.post("/api/clients")
    async def api_add_client(payload: dict[str, Any]):
        name = str(payload.get("name") or "").strip()
        path = str(payload.get("db_path") or "").strip()
        notes = str(payload.get("notes") or "").strip()
        enabled = bool(payload.get("enabled", True))
        smb_username = str(payload.get("smb_username") or "").strip()
        smb_password = str(payload.get("smb_password") or "")
        if not name or not path:
            return JSONResponse({"error": "name and db_path are required"}, status_code=400)
        try:
            def _add(conn):
                client = add_client(
                    conn,
                    name,
                    path,
                    notes=notes,
                    enabled=enabled,
                    smb_username=smb_username,
                    smb_password=smb_password,
                )
                log_activity(
                    conn,
                    f"Added client {client['name']}",
                    level="success",
                    source="clients",
                )
                return client

            client = state.store.run(_add)
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return JSONResponse(public_client(client))

    @app.post("/api/clients/{client_id}")
    async def api_update_client(client_id: int, payload: dict[str, Any]):
        name = payload.get("name")
        db_path_val = payload.get("db_path")
        if name is not None and not str(name).strip():
            return JSONResponse({"error": "name is required"}, status_code=400)
        if db_path_val is not None and not str(db_path_val).strip():
            return JSONResponse({"error": "db_path is required"}, status_code=400)
        try:
            def _update(conn):
                password = payload.get("smb_password")
                if password == "":
                    password = None
                client = update_client(
                    conn,
                    client_id,
                    name=name,
                    db_path=db_path_val,
                    notes=payload.get("notes"),
                    enabled=payload.get("enabled"),
                    smb_username=payload.get("smb_username"),
                    smb_password=password,
                )
                if client:
                    log_activity(
                        conn,
                        f"Updated client {client['name']}",
                        level="info",
                        source="clients",
                    )
                return client

            client = state.store.run(_update)
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        if not client:
            return JSONResponse({"error": "client not found"}, status_code=404)
        return JSONResponse(public_client(client))

    @app.delete("/api/clients/{client_id}")
    async def api_delete_client(client_id: int):
        def _delete(conn):
            existing = get_client(conn, client_id)
            if not existing:
                return False
            name = existing["name"]
            ok = delete_client(conn, client_id)
            if ok:
                log_activity(
                    conn,
                    f"Deleted client {name}",
                    level="warning",
                    source="clients",
                )
            return ok

        ok = state.store.run(_delete)
        if not ok:
            return JSONResponse({"error": "client not found"}, status_code=404)
        return JSONResponse({"ok": True})

    @app.post("/api/ingest")
    async def api_ingest():
        results = await asyncio.to_thread(ingest_all, state.store)
        return JSONResponse({"results": results})

    @app.post("/api/ingest/{client_id}")
    async def api_ingest_one(client_id: int):
        if not state.store.run(lambda c: get_client(c, client_id)):
            return JSONResponse({"error": "client not found"}, status_code=404)
        result = await asyncio.to_thread(ingest_client, state.store, client_id)
        return JSONResponse(result)

    @app.get("/api/status")
    async def api_status():
        return JSONResponse(
            {
                "version": __version__,
                "stats": state.store.run(dashboard_stats),
                "clients": _public_clients(state),
                "interval": state.interval,
            }
        )

    def _packet_public(row: dict[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["local_time"] = format_local_time(row.get("CaptureDate"))
        item["unix_ts"] = to_unix_ts(row.get("CaptureDate"))
        return item

    @app.get("/api/packets")
    async def api_packets(
        q: str = "",
        client_id: int | None = None,
        tag: str = "",
        limit: int = 100,
        offset: int = 0,
    ):
        page_size = max(1, min(limit, 200))
        off = max(0, offset)
        packets = state.store.run(
            lambda c: recent_packets(
                c,
                limit=page_size,
                offset=off,
                query=q.strip() or None,
                client_id=client_id,
                tag=tag.strip() or None,
            )
        )
        return JSONResponse(
            {
                "packets": [_packet_public(p) for p in packets],
                "offset": off,
                "limit": page_size,
                "has_more": len(packets) == page_size,
            }
        )

    @app.post("/api/devices/friendly")
    async def api_set_friendly(payload: dict[str, Any]):
        mac = str(payload.get("mac") or "").strip()
        if not mac:
            return JSONResponse({"error": "mac is required"}, status_code=400)
        if "friendly" not in payload:
            return JSONResponse({"error": "friendly is required"}, status_code=400)
        friendly = bool(payload.get("friendly"))
        name = payload.get("name")
        device_type = payload.get("device_type")
        if name is not None:
            name = str(name).strip() or None
        if device_type is not None:
            device_type = str(device_type).strip() or None

        def _set(conn):
            device = set_friendly(
                conn,
                mac,
                friendly,
                name=name,
                device_type=device_type,
            )
            label = device.get("name") or device["mac"]
            if friendly:
                log_activity(
                    conn,
                    f"Marked {label} ({device['mac']}) friendly",
                    level="success",
                    source="devices",
                )
            else:
                log_activity(
                    conn,
                    f"Marked {label} ({device['mac']}) not friendly",
                    level="warning",
                    source="devices",
                )
            return device

        return JSONResponse(state.store.run(_set))

    @app.get("/api/tags")
    async def api_list_tags():
        return JSONResponse({"tags": state.store.run(list_tags)})

    @app.post("/api/tags")
    async def api_add_tag(payload: dict[str, Any]):
        mac = str(payload.get("mac") or "").strip()
        tag = str(payload.get("tag") or "").strip()
        if not mac or not tag:
            return JSONResponse({"error": "mac and tag are required"}, status_code=400)
        try:
            def _add(conn):
                result = add_tag_for_mac(conn, mac, tag)
                log_activity(
                    conn,
                    f"Tagged {result['mac']} as {result['tag']} "
                    f"({result['packets_tagged']} packets)",
                    level="info",
                    source="tags",
                )
                return result

            return JSONResponse(state.store.run(_add))
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    @app.delete("/api/tags")
    async def api_remove_tag(mac: str, tag: str):
        mac = mac.strip()
        tag = tag.strip()
        if not mac or not tag:
            return JSONResponse({"error": "mac and tag are required"}, status_code=400)

        def _remove(conn):
            result = remove_tag_for_mac(conn, mac, tag)
            log_activity(
                conn,
                f"Removed tag {result['tag']} from {result['mac']}",
                level="info",
                source="tags",
            )
            return result

        return JSONResponse(state.store.run(_remove))

    @app.get("/api/log")
    async def api_log(limit: int = 80):
        return JSONResponse({"log": state.store.run(lambda c: list_activity(c, limit))})

    @app.post("/api/log/clear")
    async def api_log_clear():
        state.store.run(clear_activity)
        return JSONResponse({"ok": True})

    @app.post("/api/devices/import-fing")
    async def api_import_fing(payload: Any):
        try:
            devices = devices_from_fing(payload)
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        if not devices:
            return JSONResponse({"error": "no devices found in Fing export"}, status_code=400)

        def _import(conn):
            result = upsert_devices(conn, devices)
            tagged = apply_friendly_to_packets(conn)
            log_activity(
                conn,
                f"{SOURCE_FING}: {result['inserted']} new, {result['updated']} updated, "
                f"{tagged} packets tagged friendly",
                level="success",
                source="devices",
            )
            return {**result, "packets_tagged": tagged, "source": SOURCE_FING}

        return JSONResponse(state.store.run(_import))

    return app
