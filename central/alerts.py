"""Voice alerts driven by newly ingested packets and Chatterbox TTS."""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from central.chatterbox import (
    ChatterboxError,
    apply_voice_override,
    chatterbox_defaults,
    get_or_synthesize_speech,
)
from central.db import (
    Store,
    VOICE_ALERT_TYPES,
    claim_voice_alert,
    enqueue_voice_alert,
    ensure_chatterbox_settings,
    get_chatterbox_settings,
    last_packet_snapshot,
    list_tracked_devices,
    log_activity,
    presence_window_minutes,
    update_device_presence,
    voice_alert_on_cooldown,
)

MAX_ALERTS_PER_CYCLE = 8


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def live_chatterbox(store: Store, yaml_settings: dict[str, Any], cache_dir: Path) -> dict[str, Any]:
    defaults = chatterbox_defaults(
        yaml_settings.get("chatterbox_tts")
        if isinstance(yaml_settings.get("chatterbox_tts"), dict)
        else yaml_settings.get("chatterbox")
        if isinstance(yaml_settings.get("chatterbox"), dict)
        else {}
    )
    voice = (
        defaults["reference_audio_filename"]
        if defaults["voice_mode"] == "clone"
        else defaults["predefined_voice_id"]
    )

    def _run(conn):
        ensure_chatterbox_settings(
            conn,
            enabled=defaults["enabled"],
            base_url=defaults["base_url"],
            voice_mode=defaults["voice_mode"],
            voice=voice,
            output_format=defaults["output_format"],
            timeout=defaults["timeout"],
            cooldown_seconds=defaults["cooldown_seconds"],
        )
        cfg = get_chatterbox_settings(conn)
        return cfg or defaults

    cfg = store.run(_run)
    cfg = apply_voice_override(
        cfg, voice_mode=cfg.get("voice_mode"), voice=cfg.get("voice")
    )
    cfg["cache_dir"] = str(cache_dir)
    cfg["split_text"] = False
    return cfg


def _is_mobile(device_type: str | None) -> bool:
    return "mobile" in str(device_type or "").lower() or "phone" in str(device_type or "").lower()


def _format_alert(template: str, *, name: str, mac: str) -> str:
    spoken_name = name.strip() if name.strip() else "unknown"
    try:
        return template.format(name=spoken_name, mac=mac).strip()
    except (KeyError, ValueError):
        return template.replace("{name}", spoken_name).replace("{mac}", mac)


_CAPTURE_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
)


def _parse_capture(value: Any) -> datetime | None:
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
        for fmt in _CAPTURE_FORMATS:
            try:
                parsed = datetime.strptime(str(value).strip(), fmt)
                return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
            except ValueError:
                continue
    return None


def friendly_recently_seen(
    last_prior_capture: Any,
    last_new_capture: Any,
    quiet_minutes: int,
) -> bool:
    """True if this friendly MAC was already detected inside the quiet window."""
    minutes = max(1, int(quiet_minutes))
    prior = _parse_capture(last_prior_capture)
    if prior is None:
        return False
    latest = _parse_capture(last_new_capture) or datetime.now(timezone.utc).replace(tzinfo=None)
    return latest - prior < timedelta(minutes=minutes)


def seen_within_minutes(capture: Any, minutes: int, *, now: datetime | None = None) -> bool:
    last = _parse_capture(capture)
    if last is None:
        return False
    current = now or datetime.now(timezone.utc).replace(tzinfo=None)
    if current.tzinfo:
        current = current.replace(tzinfo=None)
    return current - last < timedelta(minutes=max(1, int(minutes)))


def next_presence(current: str | None, seen_recently: bool) -> tuple[str, str | None]:
    """Return (new_presence, alert_id or None) for a tracked device."""
    if seen_recently:
        if current == "away":
            return "inside", "entered_premises"
        return "inside", None
    if current == "inside":
        return "away", "left_premises"
    return "away", None


def evaluate_tracked_presence(
    conn,
    alerts_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Update tracked-device presence and return leave/enter alerts to speak."""
    minutes = presence_window_minutes(conn)
    events: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for device in list_tracked_devices(conn):
        mac = str(device.get("mac") or "")
        if not mac:
            continue
        snap = last_packet_snapshot(conn, mac)
        capture = snap.get("capture_date")
        seen = seen_within_minutes(capture, minutes, now=now)
        new_presence, event_id = next_presence(device.get("presence"), seen)
        log_event = None
        arrived_at = None
        departed_at = None
        if event_id == "entered_premises":
            log_event = "entered"
            arrived_at = capture
        elif event_id == "left_premises":
            log_event = "left"
            departed_at = capture
        elif new_presence == "inside":
            arrived_at = capture
        else:
            departed_at = capture
        update_device_presence(
            conn,
            mac,
            presence=new_presence,
            last_signal=snap.get("signal"),
            arrived_at=arrived_at,
            departed_at=departed_at,
            log_event=log_event,
        )
        if not event_id:
            continue
        spec = alerts_by_id.get(event_id) or {}
        name = (
            str(device.get("spoken_name") or device.get("name") or snap.get("packet_name") or "").strip()
            or mac
        )
        template = str(spec.get("template") or "")
        if event_id == "left_premises" and not template:
            template = "{name} has left the premises."
        if event_id == "entered_premises" and not template:
            template = "{name} has entered the premises."
        events.append(
            {
                "id": event_id,
                "mac": mac,
                "text": _format_alert(template, name=name, mac=mac),
            }
        )
    return events


def collect_alert_events(
    conn, since: str, *, recent_minutes: int = 5
) -> list[dict[str, Any]]:
    minutes = max(1, min(int(recent_minutes), 1440))
    rows = conn.execute(
        """
        SELECT
            REPLACE(UPPER(p.SourceMAC), '-', ':') AS mac,
            MAX(p.DeviceType) AS device_type,
            MAX(NULLIF(p.FriendlyName, '')) AS packet_name,
            MAX(d.name) AS device_name,
            MAX(NULLIF(d.spoken_name, '')) AS spoken_name,
            MAX(IFNULL(d.friendly, 0)) AS friendly,
            SUM(CASE WHEN p.ingested_at >= ? THEN 1 ELSE 0 END) AS new_packets,
            SUM(CASE WHEN p.ingested_at < ? THEN 1 ELSE 0 END) AS prior_packets,
            SUM(
                CASE WHEN datetime(p.CaptureDate) >= datetime('now', ?)
                     THEN 1 ELSE 0 END
            ) AS recent_packets,
            MAX(CASE WHEN p.ingested_at < ? THEN p.CaptureDate END) AS last_prior_capture,
            MAX(CASE WHEN p.ingested_at >= ? THEN p.CaptureDate END) AS last_new_capture
        FROM Packet p
        LEFT JOIN Device d
          ON d.mac = REPLACE(UPPER(p.SourceMAC), '-', ':')
        WHERE p.SourceMAC IS NOT NULL AND p.SourceMAC != ''
          AND REPLACE(UPPER(p.SourceMAC), '-', ':') IN (
              SELECT DISTINCT REPLACE(UPPER(SourceMAC), '-', ':')
                FROM Packet
               WHERE ingested_at >= ?
                 AND SourceMAC IS NOT NULL AND SourceMAC != ''
          )
        GROUP BY 1
        """,
        (since, since, f"-{minutes} minutes", since, since, since),
    ).fetchall()
    return [dict(r) for r in rows]


def choose_alert(row: dict[str, Any], enabled: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    mac = str(row.get("mac") or "")
    name = str(
        row.get("spoken_name") or row.get("device_name") or row.get("packet_name") or ""
    ).strip()
    friendly = bool(row.get("friendly"))
    new = int(row.get("prior_packets") or 0) == 0
    mobile = _is_mobile(row.get("device_type"))

    if friendly:
        if "friendly" not in enabled:
            return None
        spec = enabled["friendly"]
        quiet = max(1, int(spec.get("quiet_minutes") or 30))
        if friendly_recently_seen(
            row.get("last_prior_capture"),
            row.get("last_new_capture"),
            quiet,
        ):
            return None
        return {
            "id": "friendly",
            "mac": mac,
            "text": _format_alert(spec["template"], name=name or "friendly", mac=mac),
        }
    if new and mobile and "new_phone" in enabled:
        spec = enabled["new_phone"]
        return {
            "id": "new_phone",
            "mac": mac,
            "text": _format_alert(spec["template"], name=name, mac=mac),
        }
    if new and "new_device" in enabled:
        spec = enabled["new_device"]
        return {
            "id": "new_device",
            "mac": mac,
            "text": _format_alert(spec["template"], name=name, mac=mac),
        }
    if (not friendly) and "intruder" in enabled:
        spec = enabled["intruder"]
        needed = max(1, int(spec.get("min_packets") or 5))
        recent = int(row.get("recent_packets") or 0)
        if recent < needed:
            return None
        return {
            "id": "intruder",
            "mac": mac,
            "text": _format_alert(spec["template"], name=name, mac=mac),
        }
    return None


def _play_local(path: str) -> None:
    file = Path(path)
    if not file.is_file():
        return
    for cmd in (
        ["paplay", str(file)],
        ["aplay", "-q", str(file)],
        ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", str(file)],
    ):
        if shutil.which(cmd[0]):
            try:
                subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError:
                return
            return


def speak_text(cfg: dict[str, Any], text: str) -> tuple[bytes, str, bool, str]:
    return get_or_synthesize_speech(text, settings=cfg)


def dispatch_voice_alerts(
    store: Store,
    *,
    since: str,
    yaml_settings: dict[str, Any],
    cache_dir: Path,
) -> list[dict[str, Any]]:
    cfg = live_chatterbox(store, yaml_settings, cache_dir)
    alerts_by_id = {a["id"]: a for a in (cfg.get("alerts") or [])}
    enabled = {k: v for k, v in alerts_by_id.items() if v.get("enabled")}

    def _claim(conn, alert, claimed_phrases, claimed_devices, cooldown):
        phrase = " ".join(alert["text"].strip().lower().split())
        device_key = (alert["id"], alert["mac"])
        if phrase in claimed_phrases or device_key in claimed_devices:
            return False
        if voice_alert_on_cooldown(
            conn,
            alert["id"],
            alert["mac"],
            cooldown,
            text=alert["text"],
        ):
            return False
        log_id = claim_voice_alert(
            conn,
            alert_id=alert["id"],
            mac=alert["mac"],
            text=alert["text"],
        )
        alert["log_id"] = log_id
        claimed_phrases.add(phrase)
        claimed_devices.add(device_key)
        return True

    def _candidates(conn):
        presence_events = evaluate_tracked_presence(conn, alerts_by_id)
        if not cfg.get("enabled") or not enabled:
            conn.commit()
            return []
        chosen: list[dict[str, Any]] = []
        cooldown = int(cfg.get("cooldown_seconds") or 120)
        claimed_phrases: set[str] = set()
        claimed_devices: set[tuple[str, str]] = set()
        for alert in presence_events:
            if alert["id"] not in enabled:
                continue
            if _claim(conn, alert, claimed_phrases, claimed_devices, cooldown):
                chosen.append(alert)
            if len(chosen) >= MAX_ALERTS_PER_CYCLE:
                conn.commit()
                return chosen
        recent_minutes = 5
        if "intruder" in enabled:
            recent_minutes = int(enabled["intruder"].get("window_minutes") or 5)
        rows = collect_alert_events(conn, since, recent_minutes=recent_minutes)
        for row in rows:
            alert = choose_alert(row, enabled)
            if not alert:
                continue
            if _claim(conn, alert, claimed_phrases, claimed_devices, cooldown):
                chosen.append(alert)
            if len(chosen) >= MAX_ALERTS_PER_CYCLE:
                break
        conn.commit()
        return chosen

    events = store.run(_candidates)
    spoken: list[dict[str, Any]] = []
    for event in events:
        try:
            _audio, _ctype, from_cache, path = speak_text(cfg, event["text"])
        except ChatterboxError as exc:
            store.run(
                lambda c, msg=str(exc), ev=event: log_activity(
                    c,
                    f"Voice alert {ev['id']} failed: {msg}",
                    level="warning",
                    source="alerts",
                )
            )
            continue

        def _record(conn, ev=event, audio_path=path, cached=from_cache):
            qid = enqueue_voice_alert(
                conn,
                alert_id=ev["id"],
                mac=ev["mac"],
                text=ev["text"],
                audio_path=audio_path,
                log_id=ev.get("log_id"),
            )
            label = next(
                (a["label"] for a in VOICE_ALERT_TYPES if a["id"] == ev["id"]), ev["id"]
            )
            log_activity(
                conn,
                f"Voice alert: {label} — {ev['text']}"
                + (" (cached)" if cached else ""),
                level="success",
                source="alerts",
            )
            return qid

        queue_id = store.run(_record)
        _play_local(path)
        spoken.append({**event, "queue_id": queue_id, "audio_path": path})
    return spoken
