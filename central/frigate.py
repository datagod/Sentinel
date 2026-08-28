"""Client for a local Frigate NVR HTTP API."""

from __future__ import annotations

import json
import re
import time
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
        "severity": extra.get("max_severity") or "",
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
        parsed = _review_from_raw(item)
        if parsed:
            reviews.append(parsed)
    reviews.sort(key=lambda r: float(r["start_time"] or 0), reverse=True)
    return reviews


def _as_ts(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n > 1e12:
        n = n / 1000.0
    return n


def _closed_end(start: float, end: Any, *, now: float | None = None) -> float:
    resolved = _as_ts(end)
    if resolved is None:
        return max(start, now if now is not None else time.time())
    return resolved if resolved >= start else start


def _review_label(item: dict[str, Any]) -> str:
    subs = item.get("sub_labels") or []
    objs = item.get("objects") or []
    if isinstance(subs, list) and any(str(s).strip() for s in subs):
        return ", ".join(str(s).strip() for s in subs if str(s).strip())
    if isinstance(objs, list) and any(str(o).strip() for o in objs):
        return ", ".join(str(o).strip() for o in objs if str(o).strip())
    return str(item.get("title") or item.get("severity") or "activity")


def _review_from_raw(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not item.get("id"):
        return None
    rid = str(item["id"])
    extra = item.get("data") if isinstance(item.get("data"), dict) else {}
    meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    observations = meta.get("observations") or []
    if not isinstance(observations, list):
        observations = [str(observations)]
    detections = extra.get("detections") or []
    if not isinstance(detections, list):
        detections = []
    return {
        "id": rid,
        "camera": item.get("camera") or "",
        "severity": item.get("severity") or "",
        "start_time": item.get("start_time"),
        "end_time": item.get("end_time"),
        "objects": extra.get("objects") or [],
        "sub_labels": extra.get("sub_labels") or [],
        "detections": [str(d) for d in detections if d],
        "title": meta.get("title") or "",
        "summary": meta.get("shortSummary") or "",
        "scene": meta.get("scene") or "",
        "observations": [str(o).strip() for o in observations if str(o).strip()],
        "threat": meta.get("potential_threat_level"),
        "concerns": meta.get("other_concerns") or "",
        "preview": f"/api/frigate/review/{rid}/preview",
    }


def events_by_ids(base_url: str, ids: list[str]) -> list[dict[str, Any]]:
    clean: list[str] = []
    seen: set[str] = set()
    for raw in ids:
        eid = str(raw).strip()
        if not eid or eid in seen or not EVENT_ID_RE.match(eid):
            continue
        seen.add(eid)
        clean.append(eid)
    if not clean:
        return []
    events: list[dict[str, Any]] = []
    for i in range(0, len(clean), 30):
        batch = clean[i : i + 30]
        status, body, _ = _get(
            _url(base_url, "/event_ids", {"ids": ",".join(batch)}),
            timeout=10,
        )
        if status != 200:
            continue
        try:
            raw = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            continue
        rows = raw if isinstance(raw, list) else [raw]
        for item in rows:
            parsed = _event_from_raw(item)
            if parsed:
                events.append(parsed)
    return events


def review_by_id(base_url: str, review_id: str) -> dict[str, Any] | None:
    if not EVENT_ID_RE.match(review_id):
        return None
    status, body, _ = _get(_url(base_url, f"/review/{review_id}"), timeout=10)
    if status != 200:
        return None
    try:
        raw = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    return _review_from_raw(raw)


def review_preview_bytes(base_url: str, review_id: str) -> tuple[bytes, str]:
    if not EVENT_ID_RE.match(review_id):
        raise FrigateError("invalid review")
    status, body, ctype = _get(
        _url(base_url, f"/review/{review_id}/preview"),
        timeout=30,
    )
    if status != 200 or not body:
        raise FrigateError(f"no preview for review {review_id}")
    return body, ctype or "image/gif"


def windows_covering(
    ts: float, windows: list[dict[str, Any]], slack: float = 1.0
) -> list[dict[str, Any]]:
    return [
        w
        for w in windows
        if (float(w["start_time"]) - slack) <= ts <= (float(w["end_time"]) + slack)
    ]


def detection_windows(
    base_url: str,
    start: float,
    end: float,
    *,
    exclude_cameras: list[str] | None = None,
    lookback_seconds: int = 300,
) -> list[dict[str, Any]]:
    """Alert/detection windows that can overlap packets between start and end."""
    names = active_cameras(base_url, exclude=exclude_cameras)
    if not names:
        return []
    allowed = set(names)
    query_start = float(start) - max(0, int(lookback_seconds))
    query_end = float(end)
    reviews = [
        r
        for r in reviews_in_range(base_url, query_start, query_end, limit=100)
        if r.get("camera") in allowed
    ]
    events = [
        e
        for e in events_in_range(base_url, query_start, query_end, limit=100)
        if e.get("camera") in allowed
    ]
    by_id = {e["id"]: e for e in events}
    missing: list[str] = []
    for review in reviews:
        for eid in review.get("detections") or []:
            if eid not in by_id:
                missing.append(str(eid))
    for ev in events_by_ids(base_url, missing):
        if ev.get("camera") in allowed:
            by_id[ev["id"]] = ev
            events.append(ev)

    now = time.time()
    windows: list[dict[str, Any]] = []
    covered: set[str] = set()
    for review in reviews:
        nested = [by_id[i] for i in (review.get("detections") or []) if i in by_id]
        starts: list[float] = []
        ends: list[float] = []
        rs = _as_ts(review.get("start_time"))
        if rs is not None:
            starts.append(rs)
            ends.append(_closed_end(rs, review.get("end_time"), now=now))
        for ev in nested:
            es = _as_ts(ev.get("start_time"))
            if es is None:
                continue
            starts.append(es)
            ends.append(_closed_end(es, ev.get("end_time"), now=now))
        if not starts:
            continue
        wstart = min(starts)
        wend = max(ends) if ends else wstart
        event_ids = [ev["id"] for ev in nested]
        covered.update(event_ids)
        windows.append(
            {
                "kind": "review",
                "id": review["id"],
                "camera": review.get("camera") or "",
                "severity": review.get("severity") or "detection",
                "label": _review_label(review),
                "start_time": wstart,
                "end_time": wend,
                "event_ids": event_ids,
            }
        )
    for ev in events:
        if ev["id"] in covered:
            continue
        es = _as_ts(ev.get("start_time"))
        if es is None:
            continue
        windows.append(
            {
                "kind": "event",
                "id": ev["id"],
                "camera": ev.get("camera") or "",
                "severity": ev.get("severity") or "detection",
                "label": ev.get("label") or "object",
                "start_time": es,
                "end_time": _closed_end(es, ev.get("end_time"), now=now),
                "event_ids": [ev["id"]],
            }
        )
    windows.sort(key=lambda w: float(w["start_time"]), reverse=True)
    return windows


def _camera_card(camera: str, start: float, end: float) -> dict[str, Any]:
    clip_end = end if end > start else start + 1
    return {
        "camera": camera,
        "segments": 1,
        "has_detection": True,
        "snapshot": f"/api/frigate/snapshot/{camera}?ts={start}",
        "clip": f"/api/frigate/clip/{camera}?start={start}&end={clip_end}",
    }


def incidents(
    base_url: str,
    *,
    review_ids: list[str] | None = None,
    event_ids: list[str] | None = None,
    exclude_cameras: list[str] | None = None,
) -> dict[str, Any]:
    """Load specific Frigate alerts/detections (not a padded packet lookup)."""
    names = active_cameras(base_url, exclude=exclude_cameras)
    allowed = set(names)
    empty = {
        "ts": 0,
        "snapshot_ts": 0,
        "start": 0,
        "end": 0,
        "pad_seconds": 0,
        "lead_seconds": 0,
        "events": [],
        "reviews": [],
        "cameras": [],
        "detection_cameras": [],
        "other_cameras": [],
        "incident_mode": True,
    }
    if not names:
        return empty
    reviews: list[dict[str, Any]] = []
    for rid in review_ids or []:
        row = review_by_id(base_url, rid)
        if row and row.get("camera") in allowed:
            reviews.append(row)

    wanted: list[str] = []
    seen: set[str] = set()
    for review in reviews:
        for eid in review.get("detections") or []:
            if eid not in seen:
                seen.add(eid)
                wanted.append(eid)
    for eid in event_ids or []:
        text = str(eid).strip()
        if text and text not in seen:
            seen.add(text)
            wanted.append(text)
    events = [
        e for e in events_by_ids(base_url, wanted) if e.get("camera") in allowed
    ]

    by_cam: dict[str, tuple[float, float]] = {}
    now = time.time()

    def _span(camera: str, start: float | None, end: Any) -> None:
        if not camera or start is None:
            return
        closed = _closed_end(start, end, now=now)
        prev = by_cam.get(camera)
        by_cam[camera] = (min(prev[0], start), max(prev[1], closed)) if prev else (start, closed)

    for review in reviews:
        _span(
            str(review.get("camera") or ""),
            _as_ts(review.get("start_time")),
            review.get("end_time"),
        )
    for ev in events:
        _span(
            str(ev.get("camera") or ""),
            _as_ts(ev.get("start_time")),
            ev.get("end_time"),
        )

    cameras = [_camera_card(cam, span[0], span[1]) for cam, span in sorted(by_cam.items())]
    starts = [span[0] for span in by_cam.values()]
    ends = [span[1] for span in by_cam.values()]
    ts = min(starts) if starts else 0.0
    return {
        "ts": ts,
        "snapshot_ts": ts,
        "start": ts,
        "end": max(ends) if ends else ts,
        "pad_seconds": 0,
        "lead_seconds": 0,
        "events": events,
        "reviews": reviews,
        "cameras": cameras,
        "detection_cameras": cameras,
        "other_cameras": [],
        "incident_mode": True,
    }


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
