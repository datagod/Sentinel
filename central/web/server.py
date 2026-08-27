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
from central.alerts import dispatch_voice_alerts, live_chatterbox, speak_text
from central.chatterbox import ChatterboxError, list_voices as chatterbox_list_voices
from central.wigle import (
    WigleError,
    fetch_usage as wigle_fetch_usage,
    search_ssid as wigle_search_ssid,
    test_connection as wigle_test_connection,
)
from central.tts_cache import (
    delete_recordings,
    list_recordings,
    media_type_for_filename,
    normalize_recordings_dir,
    recording_file_path,
    resolve_recordings_dir,
    safe_recording_filename,
)
from central.config import db_path, data_dir, frigate_settings, seed_clients, wigle_yaml
from central.tiles import TileError, get_tile, tiles_dir
from central.frigate import (
    CAMERA_RE,
    FrigateError,
    clip_iter,
    event_bytes,
    event_clip_iter,
    list_cameras as frigate_list_cameras,
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
    devices_for_map,
    ensure_frigate_settings,
    ensure_wigle_settings,
    get_client,
    get_device,
    get_frigate_settings,
    get_wigle_settings,
    get_wigle_cache,
    get_packet,
    get_voice_alert_queue_item,
    list_pending_voice_alerts,
    mac_stats,
    mark_voice_alert_played,
    list_activity,
    list_clients,
    list_devices,
    list_tags,
    log_activity,
    public_client,
    recent_packets,
    save_chatterbox_settings,
    save_wigle_settings,
    save_wigle_cache,
    save_frigate_settings,
    sensor_gps,
    seed_clients as seed_db_clients,
    set_frigate_camera_enabled,
    save_voice_alert,
    set_voice_alert_enabled,
    suspicious_activity,
    remove_tag_for_mac,
    set_friendly,
    set_tracked,
    update_client,
    upsert_devices,
    upsert_frigate_cameras,
)
from central.fing_import import SOURCE_FING, devices_from_fing
from central.ingest import ingest_all, ingest_client
from central.map_plot import plot_device

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
        normalize_recordings_dir(data_dir(settings) / "localrecordings")

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


def _yaml_frigate(state: AppState) -> dict[str, Any]:
    return frigate_settings(state.settings)


def _live_frigate(state: AppState) -> dict[str, Any]:
    defaults = _yaml_frigate(state)

    def _run(conn):
        ensure_frigate_settings(
            conn,
            base_url=defaults["base_url"],
            pad_seconds=defaults["pad_seconds"],
            lead_seconds=defaults["lead_seconds"],
            cameras=defaults.get("cameras") or [],
        )
        cfg = get_frigate_settings(conn)
        return cfg or defaults

    return state.store.run(_run)


def _sync_frigate_cameras(state: AppState, cfg: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    error = None
    live: list[str] = []
    try:
        live = frigate_list_cameras(cfg["base_url"])
    except FrigateError as exc:
        error = str(exc)
    cameras = state.store.run(lambda c: upsert_frigate_cameras(c, live))
    return cameras, error


def _tts_cache_dir(state: AppState) -> Path:
    path = data_dir(state.settings) / "localrecordings"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _live_chatterbox(state: AppState) -> dict[str, Any]:
    return live_chatterbox(state.store, state.settings, _tts_cache_dir(state))


def _live_wigle(state: AppState, *, include_secret: bool = False) -> dict[str, Any]:
    defaults = wigle_yaml(state.settings)

    def _run(conn):
        ensure_wigle_settings(
            conn,
            enabled=defaults["enabled"],
            base_url=defaults["base_url"],
            api_name=defaults["api_name"],
            api_token=defaults["api_token"],
        )
        cfg = get_wigle_settings(conn, include_secret=include_secret)
        return cfg or {
            "enabled": False,
            "base_url": defaults["base_url"],
            "api_name": defaults["api_name"],
            "has_api_token": bool(defaults.get("api_token")),
        }

    return state.store.run(_run)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _optional_int(value: str | int | None) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _ingest_all_with_alerts(state: AppState):
    started = _now_utc()
    results = ingest_all(state.store)
    dispatch_voice_alerts(
        state.store,
        since=started,
        yaml_settings=state.settings,
        cache_dir=_tts_cache_dir(state),
    )
    return results


def _map_payload(state: AppState, hours: int) -> dict[str, Any]:
    hours = max(1, min(int(hours), 168))
    center = state.store.run(sensor_gps)
    raw = state.store.run(lambda c: devices_for_map(c, hours=hours))
    devices: list[dict[str, Any]] = []
    if center:
        clat = float(center["lat"])
        clon = float(center["lon"])
        for row in raw:
            mac = str(row.get("mac") or "")
            plotted = plot_device(
                clat,
                clon,
                mac=mac,
                signal=row.get("strongest_signal"),
                band=row.get("band"),
            )
            if not plotted:
                continue
            name = row.get("name") or row.get("packet_name") or ""
            device_type = row.get("device_type") or ""
            devices.append(
                {
                    "mac": mac,
                    "name": name,
                    "vendor": row.get("vendor") or "",
                    "device_type": device_type,
                    "friendly": bool(row.get("friendly")),
                    "mobile": "mobile" in device_type.lower() or "phone" in device_type.lower(),
                    "signal": row.get("strongest_signal"),
                    "band": row.get("band") or "",
                    "packets": row.get("packets") or 0,
                    "last_seen": format_local_time(row.get("last_seen")),
                    "ssids": row.get("ssid_list") or [],
                    **plotted,
                }
            )
    return {
        "hours": hours,
        "center": (
            {
                "lat": float(center["lat"]),
                "lon": float(center["lon"]),
                "client_name": center.get("client_name") or "",
                "captured_at": format_local_time(center.get("captured_at")),
            }
            if center
            else None
        ),
        "devices": devices,
        "rings_ft": (50, 100, 200, 300, 500),
    }


def _ingest_one_with_alerts(state: AppState, client_id: int):
    started = _now_utc()
    result = ingest_client(state.store, client_id)
    dispatch_voice_alerts(
        state.store,
        since=started,
        yaml_settings=state.settings,
        cache_dir=_tts_cache_dir(state),
    )
    return result


def create_app(settings: dict[str, Any]) -> FastAPI:
    state = AppState(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async def _loop() -> None:
            while True:
                try:
                    await asyncio.to_thread(_ingest_all_with_alerts, state)
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
        client_id: str | None = None,
        tag: str = "",
        limit: int = 200,
    ):
        page_size = max(1, min(limit, 200))
        client_pk = _optional_int(client_id)
        packets = state.store.run(
            lambda c: recent_packets(
                c,
                limit=page_size,
                query=q.strip() or None,
                client_id=client_pk,
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
                "client_id": client_pk,
                "tag": tag,
                "page_size": page_size,
                "has_more": len(packets) == page_size,
                "clients": _public_clients(state),
                "tags": state.store.run(list_tags),
            },
        )

    @app.get("/details", response_class=HTMLResponse)
    async def details_page(request: Request, mac: str, packet: int | None = None):
        mac = mac.strip()
        if not mac:
            return HTMLResponse("MAC is required", status_code=400)
        pkt = state.store.run(lambda c: get_packet(c, packet)) if packet else None
        if pkt is None and packet is None:
            recent = state.store.run(
                lambda c: recent_packets(c, limit=1, source_mac=mac)
            )
            pkt = recent[0] if recent else None
        device = state.store.run(lambda c: get_device(c, mac))
        summary = state.store.run(lambda c: mac_stats(c, mac))
        history = state.store.run(
            lambda c: recent_packets(c, limit=40, source_mac=mac)
        )
        return TEMPLATES.TemplateResponse(
            request,
            "details.html",
            {
                **_nav("packets", state),
                "mac": summary.get("mac") or mac,
                "packet": pkt,
                "device": device or {},
                "summary": summary,
                "history": history,
                "known_tags": state.store.run(list_tags),
            },
        )

    @app.get("/devices", response_class=HTMLResponse)
    async def devices_page(
        request: Request,
        q: str = "",
        friendly: str = "",
        tracked: str = "",
        tag: str = "",
    ):
        flag = {"1": True, "0": False, "yes": True, "no": False}.get(friendly.lower(), None)
        tracked_flag = {"1": True, "0": False, "yes": True, "no": False}.get(tracked.lower(), None)
        devices = state.store.run(
            lambda c: list_devices(
                c,
                query=q.strip() or None,
                friendly=flag,
                tracked=tracked_flag,
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
                "tracked": tracked,
                "tag": tag,
                "tags": state.store.run(list_tags),
            },
        )

    @app.get("/map", response_class=HTMLResponse)
    async def map_page(request: Request, hours: int = 8):
        hours = max(1, min(hours, 168))
        payload = _map_payload(state, hours)
        return TEMPLATES.TemplateResponse(
            request,
            "map.html",
            {
                **_nav("map", state),
                "hours": hours,
                "hour_choices": (1, 2, 4, 8, 12, 24, 48),
                "map_data": payload,
            },
        )

    @app.get("/api/map")
    async def api_map(hours: int = 8):
        return JSONResponse(_map_payload(state, hours))

    @app.get("/tiles/{z}/{x}/{y}.png")
    async def map_tile(request: Request, z: int, x: int, y: int):
        referer = (request.headers.get("referer") or "").strip() or (
            str(request.base_url).rstrip("/") + "/map"
        )
        try:
            path, source, max_age = await asyncio.to_thread(
                get_tile,
                tiles_dir(state.settings),
                z,
                x,
                y,
                referer=referer,
            )
        except TileError as exc:
            return Response(str(exc), status_code=exc.status, media_type="text/plain")
        return FileResponse(
            path,
            media_type="image/png",
            headers={
                "Cache-Control": f"public, max-age={max(60, int(max_age))}",
                "X-Tile-Cache": source,
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
                "latest_packet_id": state.store.run(
                    lambda c: int((dashboard_stats(c).get("latest_packet_id") or 0))
                ),
            },
        )

    def _report_public(row: dict[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item["last_seen_local"] = format_local_time(row.get("last_seen"))
        item["unix_ts"] = to_unix_ts(row.get("last_seen"))
        return item

    @app.get("/api/reports")
    async def api_reports(hours: int = 24):
        hours = max(1, min(hours, 168))
        rows = state.store.run(lambda c: suspicious_activity(c, hours=hours))
        return {
            "hours": hours,
            "rows": [_report_public(r) for r in rows],
            "latest_packet_id": state.store.run(
                lambda c: int((dashboard_stats(c).get("latest_packet_id") or 0))
            ),
        }

    @app.get("/audio-alerts", response_class=HTMLResponse)
    async def audio_alerts_page(request: Request):
        cb = _live_chatterbox(state)
        cache_dir = str(_tts_cache_dir(state))
        return TEMPLATES.TemplateResponse(
            request,
            "audio_alerts.html",
            {
                **_nav("audio-alerts", state),
                "chatterbox": cb,
                "cache_dir": cache_dir,
                "test_message": cb.get("default_test_message")
                or "Sentinel Central voice alert test.",
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
        fg = _live_frigate(state)
        error = None
        try:
            data = await asyncio.to_thread(
                frigate_lookup,
                fg["base_url"],
                ts,
                fg["pad_seconds"],
                None,
                fg["lead_seconds"],
                fg.get("disabled_cameras") or [],
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
        fg = _live_frigate(state)
        try:
            found = await asyncio.to_thread(
                frigate_nearest_event,
                fg["base_url"],
                ts,
                fg.get("disabled_cameras") or [],
            )
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)
        if not found:
            return JSONResponse({"error": "No Frigate detections found."}, status_code=404)
        return JSONResponse(found)

    @app.get("/api/frigate/snapshot/{camera}")
    async def frigate_snapshot(camera: str, ts: float):
        fg = _live_frigate(state)
        try:
            body, ctype = await asyncio.to_thread(
                snapshot_bytes, fg["base_url"], camera, ts
            )
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        return Response(content=body, media_type=ctype)

    @app.get("/api/frigate/event/{event_id}/snapshot.jpg")
    async def frigate_event_snapshot(event_id: str):
        fg = _live_frigate(state)
        try:
            body, ctype = await asyncio.to_thread(
                event_bytes, fg["base_url"], event_id, "snapshot.jpg"
            )
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        return Response(content=body, media_type=ctype)

    @app.get("/api/frigate/event/{event_id}/thumbnail.jpg")
    async def frigate_event_thumbnail(event_id: str):
        fg = _live_frigate(state)
        try:
            body, ctype = await asyncio.to_thread(
                event_bytes, fg["base_url"], event_id, "thumbnail.jpg"
            )
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        return Response(content=body, media_type=ctype)

    @app.get("/api/frigate/event/{event_id}/clip.mp4")
    async def frigate_event_clip(event_id: str):
        fg = _live_frigate(state)
        try:
            iterator = event_clip_iter(fg["base_url"], event_id)
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        return StreamingResponse(iterator, media_type="video/mp4")

    @app.get("/api/frigate/clip/{camera}")
    async def frigate_clip(camera: str, start: float, end: float):
        fg = _live_frigate(state)
        try:
            iterator = clip_iter(fg["base_url"], camera, start, end)
        except FrigateError as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)
        return StreamingResponse(iterator, media_type="video/mp4")

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        fg = _live_frigate(state)
        cameras, frigate_error = await asyncio.to_thread(_sync_frigate_cameras, state, fg)
        enabled_count = sum(1 for c in cameras if c.get("enabled"))
        cb = _live_chatterbox(state)
        chatterbox_error = None
        voices: dict[str, list] = {"clone": [], "predefined": []}
        try:
            voices = await asyncio.to_thread(chatterbox_list_voices, cb)
        except ChatterboxError as exc:
            chatterbox_error = str(exc)
        return TEMPLATES.TemplateResponse(
            request,
            "settings.html",
            {
                **_nav("settings", state),
                "settings": state.settings,
                "data_dir": str(data_dir(state.settings)),
                "db_path": str(db_path(state.settings)),
                "config_path": state.settings.get("_config_path", ""),
                "frigate": fg,
                "frigate_cameras": cameras,
                "frigate_error": frigate_error,
                "frigate_enabled_count": enabled_count,
                "chatterbox": cb,
                "chatterbox_voices": voices,
                "chatterbox_error": chatterbox_error,
                "wigle": _live_wigle(state),
            },
        )

    @app.post("/api/settings/frigate")
    async def api_save_frigate(payload: dict[str, Any]):
        url = str(payload.get("base_url") or "").strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            return JSONResponse(
                {"error": "Frigate URL must start with http:// or https://"},
                status_code=400,
            )
        try:
            pad = int(payload.get("pad_seconds", 15))
            lead = int(payload.get("lead_seconds", 5))
        except (TypeError, ValueError):
            return JSONResponse({"error": "pad and lead must be numbers"}, status_code=400)
        pad = max(5, min(pad, 120))
        lead = max(0, min(lead, 60))

        def _save(conn):
            saved = save_frigate_settings(
                conn, base_url=url, pad_seconds=pad, lead_seconds=lead
            )
            log_activity(
                conn,
                f"Frigate settings saved ({url}, lead {lead}s, pad {pad}s)",
                source="settings",
                commit=True,
            )
            return saved

        saved = state.store.run(_save)
        cameras, error = await asyncio.to_thread(_sync_frigate_cameras, state, saved)
        return {
            "ok": True,
            "frigate": saved,
            "cameras": cameras,
            "error": error,
        }

    @app.post("/api/settings/frigate/cameras")
    async def api_toggle_frigate_camera(payload: dict[str, Any]):
        name = str(payload.get("name") or "").strip()
        if not CAMERA_RE.match(name):
            return JSONResponse({"error": "invalid camera name"}, status_code=400)
        enabled = bool(payload.get("enabled"))

        def _save(conn):
            row = set_frigate_camera_enabled(conn, name, enabled)
            log_activity(
                conn,
                f"Frigate camera {name} {'enabled' if enabled else 'disabled'} for footage lookup",
                source="settings",
                commit=True,
            )
            return row

        row = state.store.run(_save)
        return {"ok": True, "camera": row}

    @app.post("/api/settings/frigate/cameras/refresh")
    async def api_refresh_frigate_cameras():
        fg = _live_frigate(state)
        cameras, error = await asyncio.to_thread(_sync_frigate_cameras, state, fg)
        if error and not cameras:
            return JSONResponse({"error": error, "cameras": cameras}, status_code=502)
        return {"ok": True, "cameras": cameras, "error": error}

    @app.post("/api/settings/chatterbox")
    async def api_save_chatterbox(payload: dict[str, Any]):
        url = str(payload.get("base_url") or "").strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            return JSONResponse(
                {"error": "Chatterbox URL must start with http:// or https://"},
                status_code=400,
            )
        voice_mode = str(payload.get("voice_mode") or "clone").strip().lower()
        if voice_mode not in {"clone", "predefined"}:
            return JSONResponse({"error": "voice mode must be clone or predefined"}, status_code=400)
        voice = str(payload.get("voice") or "").strip()
        if not voice:
            return JSONResponse({"error": "Choose a voice"}, status_code=400)
        try:
            timeout = int(payload.get("timeout", 60))
            cooldown = int(payload.get("cooldown_seconds", 120))
        except (TypeError, ValueError):
            return JSONResponse({"error": "timeout and cooldown must be numbers"}, status_code=400)
        enabled = bool(payload.get("enabled"))

        def _save(conn):
            saved = save_chatterbox_settings(
                conn,
                enabled=enabled,
                base_url=url,
                voice_mode=voice_mode,
                voice=voice,
                timeout=max(5, min(timeout, 180)),
                cooldown_seconds=max(15, min(cooldown, 3600)),
            )
            log_activity(
                conn,
                f"Chatterbox {'enabled' if enabled else 'disabled'} ({url}, {voice_mode}:{voice})",
                source="settings",
                commit=True,
            )
            return saved

        saved = state.store.run(_save)
        return {"ok": True, "chatterbox": saved}

    @app.post("/api/settings/wigle")
    async def api_save_wigle(payload: dict[str, Any]):
        url = str(payload.get("base_url") or "https://api.wigle.net").strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            return JSONResponse(
                {"error": "WiGLE URL must start with http:// or https://"},
                status_code=400,
            )
        api_name = str(payload.get("api_name") or "").strip()
        token_in = payload.get("api_token")
        api_token = None if token_in is None else str(token_in)
        enabled = bool(payload.get("enabled"))
        if enabled and not api_name:
            return JSONResponse({"error": "API name is required when WiGLE is enabled"}, status_code=400)
        existing = _live_wigle(state, include_secret=True)
        incoming_token = (api_token or "").strip() if api_token is not None else ""
        if enabled and not incoming_token and not existing.get("api_token"):
            return JSONResponse({"error": "API token is required when WiGLE is enabled"}, status_code=400)

        def _save(conn):
            saved = save_wigle_settings(
                conn,
                enabled=enabled,
                base_url=url,
                api_name=api_name,
                api_token=api_token,
            )
            log_activity(
                conn,
                f"WiGLE {'enabled' if enabled else 'disabled'}"
                + (f" ({api_name})" if api_name else ""),
                source="settings",
                commit=True,
            )
            return saved

        saved = state.store.run(_save)
        return {"ok": True, "wigle": saved}

    @app.post("/api/settings/wigle/test")
    async def api_test_wigle(payload: dict[str, Any] | None = None):
        body = payload or {}
        stored = _live_wigle(state, include_secret=True)
        api_name = str(body.get("api_name") or stored.get("api_name") or "").strip()
        token = str(body.get("api_token") or "").strip() or str(stored.get("api_token") or "")
        url = str(body.get("base_url") or stored.get("base_url") or "https://api.wigle.net").strip().rstrip("/")
        try:
            result = await asyncio.to_thread(
                wigle_test_connection,
                {"api_name": api_name, "api_token": token, "base_url": url},
            )
        except WigleError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)
        return {"ok": True, **result}

    @app.get("/api/wigle/usage")
    async def api_wigle_usage():
        stored = _live_wigle(state, include_secret=True)
        if not stored.get("api_name") or not stored.get("api_token"):
            return JSONResponse(
                {
                    "error": "Save WiGLE API name and token first.",
                    "settings_url": "/settings",
                },
                status_code=400,
            )
        try:
            remote = await asyncio.to_thread(wigle_fetch_usage, stored)
        except WigleError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)

        def _local(conn):
            day = conn.execute(
                """
                SELECT COUNT(*) AS n FROM ActivityLog
                 WHERE source = 'wigle'
                   AND datetime(created_at) >= datetime('now', '-24 hours')
                """
            ).fetchone()["n"]
            total = conn.execute(
                "SELECT COUNT(*) AS n FROM ActivityLog WHERE source = 'wigle'"
            ).fetchone()["n"]
            cached = conn.execute("SELECT COUNT(*) AS n FROM WigleCache").fetchone()["n"]
            return {"lookups_24h": int(day), "lookups_total": int(total), "cached_ssids": int(cached)}

        local = state.store.run(_local)
        return {"ok": True, **remote, "local": local}

    @app.get("/api/wigle/ssid")
    async def api_wigle_ssid(ssid: str):
        name = str(ssid or "").strip()
        if not name:
            return JSONResponse({"error": "ssid is required"}, status_code=400)
        cfg = _live_wigle(state, include_secret=True)
        if not cfg.get("enabled") or not cfg.get("api_token") or not cfg.get("api_name"):
            return JSONResponse(
                {
                    "error": "WiGLE is not enabled. Save API name and token under Settings first.",
                    "settings_url": "/settings",
                },
                status_code=400,
            )
        cache_key = f"{name}|2-10-100mi"
        cached = state.store.run(lambda c: get_wigle_cache(c, "ssid", cache_key))
        if cached:
            return cached
        gps = state.store.run(sensor_gps)
        if not gps or gps.get("lat") is None or gps.get("lon") is None:
            return JSONResponse(
                {"error": "No sensor GPS yet. WiGLE lookups stay within 2, 10, then 100 miles of the sensor."},
                status_code=400,
            )

        def _lookup():
            return wigle_search_ssid(
                cfg,
                name,
                lat=float(gps["lat"]),
                lon=float(gps["lon"]),
            )

        try:
            result = await asyncio.to_thread(_lookup)
        except WigleError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)

        def _store(conn):
            save_wigle_cache(conn, "ssid", cache_key, result)
            log_activity(
                conn,
                f"WiGLE SSID lookup {name!r}: {len(result.get('results') or [])} result(s) ({result.get('scope')})",
                source="wigle",
                commit=True,
            )

        state.store.run(_store)
        result["cached"] = False
        return result

    @app.post("/api/settings/alerts")
    async def api_toggle_voice_alert(payload: dict[str, Any]):
        alert_id = str(payload.get("id") or "").strip()
        enabled = payload.get("enabled")
        min_packets = payload.get("min_packets")
        window_minutes = payload.get("window_minutes")
        quiet_minutes = payload.get("quiet_minutes")
        template = payload.get("template")
        try:
            def _save(conn):
                row = save_voice_alert(
                    conn,
                    alert_id,
                    enabled=None if enabled is None else bool(enabled),
                    min_packets=min_packets,
                    window_minutes=window_minutes,
                    quiet_minutes=quiet_minutes,
                    template=template,
                )
                parts = []
                if enabled is not None:
                    parts.append("enabled" if row["enabled"] else "disabled")
                if row.get("min_packets") is not None and (
                    min_packets is not None or window_minutes is not None
                ):
                    parts.append(
                        f"{row['min_packets']} packets in {row['window_minutes']} min"
                    )
                if quiet_minutes is not None and row.get("quiet_minutes") is not None:
                    if row["id"] == "left_premises":
                        parts.append(
                            f"away after {row['quiet_minutes']} min without packets"
                        )
                    else:
                        parts.append(
                            f"after {row['quiet_minutes']} min without a detection"
                        )
                if template is not None:
                    parts.append(f"phrase “{row['template']}”")
                message = f"Voice alert {row['id']}"
                if parts:
                    message += " " + ", ".join(parts)
                log_activity(conn, message, source="settings", commit=True)
                return row

            row = state.store.run(_save)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return {"ok": True, "alert": row}

    @app.post("/api/settings/chatterbox/test")
    async def api_test_chatterbox(payload: dict[str, Any]):
        body = payload or {}
        cfg = _live_chatterbox(state)
        text = str(body.get("text") or cfg.get("default_test_message") or "").strip()
        if not text:
            text = "Sentinel Central voice alert test."
        try:
            audio, ctype, from_cache, path = await asyncio.to_thread(speak_text, cfg, text)
        except ChatterboxError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)

        def _log(conn):
            if from_cache:
                log_activity(
                    conn,
                    f"Event TTS cache hit ({text!r})",
                    source="alerts",
                    commit=True,
                )
            else:
                log_activity(
                    conn,
                    f"Event TTS generated ({text!r}), saved: {path}",
                    level="success",
                    source="alerts",
                    commit=True,
                )

        state.store.run(_log)
        return Response(
            content=audio,
            media_type=ctype,
            headers={"X-TTS-Cache": "hit" if from_cache else "miss", "X-TTS-Path": path},
        )

    @app.get("/api/recordings")
    async def api_recordings():
        cache_dir = str(_tts_cache_dir(state))
        root = resolve_recordings_dir(cache_dir)
        recordings = list_recordings(cache_dir)
        for item in recordings:
            item["local_time"] = format_local_time(item.get("modified_at"))
        return {
            "ok": True,
            "directory": str(root),
            "total": len(recordings),
            "recordings": recordings,
        }

    @app.get("/api/recordings/{filename}")
    async def api_recording_file(filename: str, download: bool = False):
        safe = safe_recording_filename(filename)
        if not safe:
            return JSONResponse({"ok": False, "error": "invalid filename"}, status_code=400)
        path = recording_file_path(safe, cache_dir=str(_tts_cache_dir(state)))
        if path is None or not path.is_file() or path.stat().st_size <= 0:
            return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
        disposition = "attachment" if download else "inline"
        headers = {
            "Content-Disposition": f'{disposition}; filename="{safe}"',
            "Cache-Control": "public, max-age=86400",
        }
        return Response(
            content=path.read_bytes(),
            media_type=media_type_for_filename(safe),
            headers=headers,
        )

    @app.post("/api/recordings/delete")
    async def api_recordings_delete(payload: dict[str, Any]):
        names = payload.get("filenames") or payload.get("files") or []
        if isinstance(names, str):
            names = [names]
        if not isinstance(names, list) or not names:
            return JSONResponse(
                {"ok": False, "error": "filenames array required"},
                status_code=400,
            )
        cache_dir = str(_tts_cache_dir(state))
        result = delete_recordings([str(n) for n in names], cache_dir=cache_dir)
        deleted = result.get("deleted") or []
        errors = result.get("errors") or {}
        if deleted:
            state.store.run(
                lambda c: log_activity(
                    c,
                    f"Deleted {len(deleted)} TTS recording(s) from {cache_dir}",
                    source="alerts",
                    commit=True,
                )
            )
        if errors and not deleted:
            return JSONResponse(
                {
                    "ok": False,
                    "deleted": deleted,
                    "errors": errors,
                    "error": "no files deleted",
                },
                status_code=400,
            )
        return {
            "ok": True,
            "deleted": deleted,
            "errors": errors,
            "remaining": len(list_recordings(cache_dir)),
        }

    @app.get("/api/alerts/pending")
    async def api_pending_alerts():
        rows = state.store.run(lambda c: list_pending_voice_alerts(c, 8))
        return {
            "alerts": [
                {
                    "id": r["id"],
                    "alert_id": r["alert_id"],
                    "mac": r["mac"],
                    "text": r["text"],
                    "audio": f"/api/alerts/{r['id']}/audio",
                }
                for r in rows
            ]
        }

    @app.get("/api/alerts/{queue_id}/audio")
    async def api_alert_audio(queue_id: int):
        item = state.store.run(lambda c: get_voice_alert_queue_item(c, queue_id))
        if not item:
            return JSONResponse({"error": "alert not found"}, status_code=404)
        path = Path(item.get("audio_path") or "")
        if not path.is_file():
            return JSONResponse({"error": "audio missing"}, status_code=404)
        suffix = path.suffix.lower().lstrip(".")
        media = {"wav": "audio/wav", "mp3": "audio/mpeg", "opus": "audio/opus"}.get(
            suffix, "application/octet-stream"
        )
        return FileResponse(path, media_type=media)

    @app.post("/api/alerts/{queue_id}/played")
    async def api_alert_played(queue_id: int):
        ok = state.store.run(lambda c: mark_voice_alert_played(c, queue_id))
        if not ok:
            return JSONResponse({"error": "alert not found"}, status_code=404)
        return {"ok": True}

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
        results = await asyncio.to_thread(_ingest_all_with_alerts, state)
        return JSONResponse({"results": results})

    @app.post("/api/ingest/{client_id}")
    async def api_ingest_one(client_id: int):
        if not state.store.run(lambda c: get_client(c, client_id)):
            return JSONResponse({"error": "client not found"}, status_code=404)
        result = await asyncio.to_thread(_ingest_one_with_alerts, state, client_id)
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
        client_id: str | None = None,
        tag: str = "",
        limit: int = 100,
        offset: int = 0,
        after_id: str | None = None,
    ):
        page_size = max(1, min(limit, 200))
        off = max(0, offset)
        newer_than = _optional_int(after_id)
        packets = state.store.run(
            lambda c: recent_packets(
                c,
                limit=page_size,
                offset=0 if newer_than else off,
                query=q.strip() or None,
                client_id=_optional_int(client_id),
                tag=tag.strip() or None,
                after_id=newer_than,
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

    @app.post("/api/devices/track")
    async def api_set_tracked(payload: dict[str, Any]):
        mac = str(payload.get("mac") or "").strip()
        if not mac:
            return JSONResponse({"error": "mac is required"}, status_code=400)
        if "tracked" not in payload:
            return JSONResponse({"error": "tracked is required"}, status_code=400)
        tracked = bool(payload.get("tracked"))

        def _set(conn):
            device = set_tracked(conn, mac, tracked)
            label = device.get("name") or device["mac"]
            if tracked:
                where = device.get("presence") or "unknown"
                log_activity(
                    conn,
                    f"Tracking {label} ({device['mac']}) · {where}",
                    level="success",
                    source="devices",
                )
            else:
                log_activity(
                    conn,
                    f"Stopped tracking {label} ({device['mac']})",
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
