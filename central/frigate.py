"""Client for a local Frigate NVR HTTP API."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator

CAMERA_RE = re.compile(r"^[A-Za-z0-9_-]+$")
EVENT_ID_RE = re.compile(r"^[\w.-]+$")


class FrigateError(Exception):
    pass


def _url(base: str, path: str, query: dict[str, Any] | None = None) -> str:
    url = base.rstrip("/") + "/api" + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    return url


def _get(url: str, timeout: float = 12) -> tuple[int, bytes, str]:
    req = urllib.request.Request(url, headers={"Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type") or "application/octet-stream"
            return resp.status, body, ctype
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() if exc.fp else b"", exc.headers.get("Content-Type") or ""
    except urllib.error.URLError as exc:
        raise FrigateError(f"Frigate unreachable: {exc.reason}") from exc


def list_cameras(base_url: str, configured: list[str] | None = None) -> list[str]:
    if configured is not None:
        return [c for c in configured if CAMERA_RE.match(c)]
    status, body, _ = _get(_url(base_url, "/config"), timeout=8)
    if status != 200:
        raise FrigateError(f"Frigate config request failed ({status})")
    data = json.loads(body.decode("utf-8"))
    cameras = list((data.get("cameras") or {}).keys())
    return [c for c in cameras if CAMERA_RE.match(c)]


def active_cameras(
    base_url: str,
    *,
    configured: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[str]:
    names = list_cameras(base_url, configured)
    if exclude:
        skip = {str(c).strip() for c in exclude if str(c).strip()}
        names = [n for n in names if n not in skip]
    return names


def camera_recordings(base_url: str, camera: str, start: float, end: float) -> list[dict[str, Any]]:
    if not CAMERA_RE.match(camera):
        return []
    status, body, _ = _get(
        _url(base_url, f"/{camera}/recordings", {"after": start, "before": end}),
        timeout=8,
    )
    if status != 200:
        return []
    try:
        data = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def lookup(
    base_url: str,
    ts: float,
    pad_seconds: int = 15,
    cameras: list[str] | None = None,
    lead_seconds: int = 5,
    exclude_cameras: list[str] | None = None,
) -> dict[str, Any]:
    pad = max(5, min(int(pad_seconds), 120))
    lead = max(0, min(int(lead_seconds), 60))
    # Packet time is slightly after the visual event; look a few seconds earlier.
    snapshot_ts = ts - lead
    start = ts - pad - lead
    end = ts + pad
    names = active_cameras(base_url, configured=cameras, exclude=exclude_cameras)
    allowed = set(names)
    raw_events = events_in_range(base_url, start, end) if names else []
    raw_reviews = reviews_in_range(base_url, start, end) if names else []
    events = [e for e in raw_events if e.get("camera") in allowed]
    reviews = [r for r in raw_reviews if r.get("camera") in allowed]
    detected = {e["camera"] for e in events} | {r["camera"] for r in reviews}
    found: list[dict[str, Any]] = []
    for name in names:
        segs = camera_recordings(base_url, name, start, end)
        if not segs:
            continue
        found.append(
            {
                "camera": name,
                "segments": len(segs),
                "has_detection": name in detected,
                "snapshot": f"/api/frigate/snapshot/{name}?ts={snapshot_ts}",
                "clip": f"/api/frigate/clip/{name}?start={start}&end={end}",
            }
        )
    found.sort(key=lambda row: (0 if row["has_detection"] else 1, row["camera"]))
    return {
        "ts": ts,
        "snapshot_ts": snapshot_ts,
        "start": start,
        "end": end,
        "pad_seconds": pad,
        "lead_seconds": lead,
        "events": events,
        "reviews": reviews,
        "cameras": found,
        "detection_cameras": found if not (events or reviews) else [c for c in found if c["has_detection"]],
        "other_cameras": [] if not (events or reviews) else [c for c in found if not c["has_detection"]],
    }


def events_in_range(
    base_url: str, start: float, end: float, limit: int = 50
) -> list[dict[str, Any]]:
    status, body, _ = _get(
        _url(
            base_url,
            "/events",
            {
                "after": start,
                "before": end,
                "limit": max(1, min(limit, 100)),
                "include_thumbnails": 0,
            },
        ),
        timeout=10,
    )
    if status != 200:
        return []
    try:
        raw = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(raw, list):
        return []
    events: list[dict[str, Any]] = []
    for item in raw:
        parsed = _event_from_raw(item)
        if parsed:
            events.append(parsed)
    events.sort(key=lambda e: float(e["start_time"] or 0), reverse=True)
    return events


def _event_from_raw(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not item.get("id"):
        return None
    eid = str(item["id"])
    extra = item.get("data") if isinstance(item.get("data"), dict) else {}
    return {
        "id": eid,
        "camera": item.get("camera") or "",
        "label": item.get("label") or "object",
        "sub_label": item.get("sub_label") or extra.get("sub_label") or "",
        "start_time": item.get("start_time"),
        "end_time": item.get("end_time"),
        "has_clip": bool(item.get("has_clip")),
        "has_snapshot": bool(item.get("has_snapshot")),
        "score": extra.get("top_score") or extra.get("score"),
        "description": extra.get("description") or "",
        "snapshot": f"/api/frigate/event/{eid}/snapshot.jpg",
        "thumbnail": f"/api/frigate/event/{eid}/thumbnail.jpg",
        "clip": f"/api/frigate/event/{eid}/clip.mp4",
    }


def _first_event(
    base_url: str,
    *,
    after: float | None = None,
    before: float | None = None,
    sort: str,
    cameras: list[str] | None = None,
) -> dict[str, Any] | None:
    query: dict[str, Any] = {
        "limit": 20 if cameras else 1,
        "include_thumbnails": 0,
        "sort": sort,
    }
    if after is not None:
        query["after"] = after
    if before is not None:
        query["before"] = before
    if cameras:
        query["cameras"] = ",".join(cameras)
    status, body, _ = _get(_url(base_url, "/events", query), timeout=10)
    if status != 200:
        return None
    try:
        raw = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, list) or not raw:
        return None
    allowed = set(cameras) if cameras is not None else None
    for item in raw:
        parsed = _event_from_raw(item)
        if not parsed:
            continue
        if allowed is not None and parsed.get("camera") not in allowed:
            continue
        return parsed
    return None


def nearest_event(
    base_url: str,
    ts: float,
    exclude_cameras: list[str] | None = None,
) -> dict[str, Any] | None:
    allowed = active_cameras(base_url, exclude=exclude_cameras)
    if exclude_cameras is not None and not allowed:
        return None
    cameras = allowed if exclude_cameras else None
    later = _first_event(base_url, after=ts, sort="date_asc", cameras=cameras)
    earlier = _first_event(base_url, before=ts, sort="date_desc", cameras=cameras)
    candidates: list[tuple[float, str, dict[str, Any]]] = []
    for event, direction in ((later, "after"), (earlier, "before")):
        if not event or event.get("start_time") is None:
            continue
        start = float(event["start_time"])
        candidates.append((abs(start - ts), direction, event))
    if not candidates:
        return None
    candidates.sort(key=lambda row: row[0])
    delta, direction, event = candidates[0]
    return {
        "ts": float(event["start_time"]),
        "delta_seconds": delta,
        "direction": direction,
        "event": event,
    }


def reviews_in_range(
    base_url: str, start: float, end: float, limit: int = 50
) -> list[dict[str, Any]]:
    status, body, _ = _get(
        _url(
            base_url,
            "/review",
            {"after": start, "before": end, "limit": max(1, min(limit, 100))},
        ),
        timeout=10,
    )
    if status != 200:
        return []
    try:
        raw = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(raw, list):
        return []
    reviews: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        extra = item.get("data") if isinstance(item.get("data"), dict) else {}
        meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        observations = meta.get("observations") or []
        if not isinstance(observations, list):
            observations = [str(observations)]
        reviews.append(
            {
                "id": str(item["id"]),
                "camera": item.get("camera") or "",
                "severity": item.get("severity") or "",
                "start_time": item.get("start_time"),
                "end_time": item.get("end_time"),
                "objects": extra.get("objects") or [],
                "sub_labels": extra.get("sub_labels") or [],
                "title": meta.get("title") or "",
                "summary": meta.get("shortSummary") or "",
                "scene": meta.get("scene") or "",
                "observations": [str(o).strip() for o in observations if str(o).strip()],
                "threat": meta.get("potential_threat_level"),
                "concerns": meta.get("other_concerns") or "",
            }
        )
    reviews.sort(key=lambda r: float(r["start_time"] or 0), reverse=True)
    return reviews


def event_bytes(base_url: str, event_id: str, filename: str) -> tuple[bytes, str]:
    if not EVENT_ID_RE.match(event_id):
        raise FrigateError("invalid event")
    if filename not in {"snapshot.jpg", "thumbnail.jpg"}:
        raise FrigateError("invalid event media")
    status, body, ctype = _get(
        _url(base_url, f"/events/{event_id}/{filename}"),
        timeout=15,
    )
    if status != 200 or not body:
        raise FrigateError(f"no {filename} for event {event_id}")
    return body, ctype or "image/jpeg"


def event_clip_iter(base_url: str, event_id: str) -> Iterator[bytes]:
    if not EVENT_ID_RE.match(event_id):
        raise FrigateError("invalid event")
    url = _url(base_url, f"/events/{event_id}/clip.mp4")
    req = urllib.request.Request(url, headers={"Accept": "video/mp4"})
    try:
        resp = urllib.request.urlopen(req, timeout=60)
    except urllib.error.URLError as exc:
        raise FrigateError(f"Frigate event clip failed: {exc}") from exc
    try:
        while True:
            chunk = resp.read(64 * 1024)
            if not chunk:
                break
            yield chunk
    finally:
        resp.close()


def snapshot_bytes(base_url: str, camera: str, ts: float) -> tuple[bytes, str]:
    if not CAMERA_RE.match(camera):
        raise FrigateError("invalid camera")
    status, body, ctype = _get(
        _url(base_url, f"/{camera}/recordings/{ts}/snapshot.jpg"),
        timeout=15,
    )
    if status != 200 or not body:
        raise FrigateError(f"no snapshot for {camera}")
    return body, ctype or "image/jpeg"


def clip_iter(base_url: str, camera: str, start: float, end: float) -> Iterator[bytes]:
    if not CAMERA_RE.match(camera):
        raise FrigateError("invalid camera")
    url = _url(base_url, f"/{camera}/start/{start}/end/{end}/clip.mp4")
    req = urllib.request.Request(url, headers={"Accept": "video/mp4"})
    try:
        resp = urllib.request.urlopen(req, timeout=60)
    except urllib.error.URLError as exc:
        raise FrigateError(f"Frigate clip failed: {exc}") from exc
    try:
        while True:
            chunk = resp.read(64 * 1024)
            if not chunk:
                break
            yield chunk
    finally:
        resp.close()
