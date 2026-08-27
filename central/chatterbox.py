"""Synchronous client for Chatterbox TTS Server (POST /tts), from frigate-tui."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from central.chatterbox_models import CHATTERBOX_TTS_MODELS, model_repo_id_from_info
from central.tts_cache import load_cached_recording, recording_path, save_recording

_MEDIA_TYPES = {
    "wav": "audio/wav",
    "mp3": "audio/mpeg",
    "opus": "audio/opus",
}


class ChatterboxError(Exception):
    pass


def chatterbox_defaults(raw: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = dict(raw or {})
    return {
        "enabled": bool(cfg.get("enabled", True)),
        "base_url": str(cfg.get("base_url") or "http://127.0.0.1:8004").rstrip("/"),
        "voice_mode": str(cfg.get("voice_mode") or "clone"),
        "reference_audio_filename": str(
            cfg.get("reference_audio_filename") or cfg.get("voice") or "JLC_William_McEvoy.mp3"
        ).strip(),
        "predefined_voice_id": str(cfg.get("predefined_voice_id") or "").strip(),
        "output_format": str(cfg.get("output_format") or "wav").lower(),
        "split_text": bool(cfg.get("split_text", False)),
        "timeout": max(5, min(int(cfg.get("timeout", 60)), 180)),
        "cooldown_seconds": max(15, min(int(cfg.get("cooldown_seconds", cfg.get("alert_cooldown", 120))), 3600)),
        "cache_dir": str(cfg.get("cache_dir") or "localrecordings").strip() or "localrecordings",
        "default_test_message": str(
            cfg.get("default_test_message") or "Sentinel Central voice alert test."
        ).strip(),
    }


def apply_voice_override(
    settings: dict[str, Any],
    *,
    voice_mode: str | None = None,
    voice: str | None = None,
) -> dict[str, Any]:
    merged = dict(settings)
    mode = (voice_mode or "").strip().lower()
    name = (voice or "").strip()
    if not mode or not name:
        return merged
    if mode == "clone":
        merged["voice_mode"] = "clone"
        merged["reference_audio_filename"] = name
    elif mode == "predefined":
        merged["voice_mode"] = "predefined"
        merged["predefined_voice_id"] = name
    return merged


def _request(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 15,
    accept: str = "application/json",
) -> tuple[int, bytes, str]:
    data = None
    headers = {"Accept": accept}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type") or ""
            return resp.status, body, ctype
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() if exc.fp else b"", exc.headers.get("Content-Type") or ""
    except urllib.error.URLError as exc:
        raise ChatterboxError(f"Chatterbox unreachable: {exc.reason}") from exc


def get_model_info(settings: dict[str, Any]) -> dict[str, Any]:
    status, body, _ = _request(
        f"{settings['base_url']}/api/model-info",
        timeout=min(15, float(settings.get("timeout", 60))),
    )
    if status != 200:
        raise ChatterboxError(f"Chatterbox model info failed ({status})")
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ChatterboxError("Chatterbox model info returned unexpected payload")
    return {
        "repo_id": model_repo_id_from_info(data),
        "info": data,
        "models": list(CHATTERBOX_TTS_MODELS),
    }


def list_voices(settings: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    base_url = settings["base_url"]
    timeout = min(15, float(settings.get("timeout", 60)))
    clones: list[dict[str, str]] = []
    predefined: list[dict[str, str]] = []
    try:
        status, body, _ = _request(f"{base_url}/get_reference_files", timeout=timeout)
        if status == 200:
            data = json.loads(body.decode("utf-8"))
            if isinstance(data, list):
                for filename in data:
                    fn = str(filename).strip()
                    if fn:
                        clones.append({"id": fn, "label": fn, "kind": "clone"})
    except ChatterboxError:
        pass
    try:
        status, body, _ = _request(f"{base_url}/get_predefined_voices", timeout=timeout)
        if status == 200:
            data = json.loads(body.decode("utf-8"))
            if isinstance(data, list):
                for entry in data:
                    if not isinstance(entry, dict):
                        continue
                    fn = str(entry.get("filename") or "").strip()
                    if not fn:
                        continue
                    label = str(entry.get("display_name") or fn).strip() or fn
                    predefined.append({"id": fn, "label": label, "kind": "predefined"})
    except ChatterboxError:
        pass
    return {"clone": clones, "predefined": predefined}


def synthesize_speech(text: str, *, settings: dict[str, Any]) -> tuple[bytes, str]:
    message = (text or "").strip()
    if not message:
        raise ChatterboxError("Text is required")
    output_format = str(settings.get("output_format") or "wav").lower()
    if output_format not in _MEDIA_TYPES:
        output_format = "wav"
    voice_mode = str(settings.get("voice_mode") or "clone")
    payload: dict[str, Any] = {
        "text": message,
        "voice_mode": voice_mode,
        "output_format": output_format,
        "split_text": bool(settings.get("split_text", False)),
        "stream": False,
    }
    if voice_mode == "clone":
        ref = str(settings.get("reference_audio_filename") or "").strip()
        if not ref:
            raise ChatterboxError("A clone voice file is required")
        payload["reference_audio_filename"] = ref
    else:
        voice_id = str(settings.get("predefined_voice_id") or "").strip()
        if not voice_id:
            raise ChatterboxError("A predefined voice is required")
        payload["predefined_voice_id"] = voice_id
    status, body, ctype = _request(
        f"{settings['base_url']}/tts",
        method="POST",
        payload=payload,
        timeout=float(settings.get("timeout", 60)),
        accept="audio/*,application/json",
    )
    if status >= 400 or not body:
        detail = body.decode("utf-8", errors="replace").strip()[:300]
        raise ChatterboxError(f"Chatterbox TTS failed ({status}): {detail or 'no audio'}")
    media_type = (ctype or "").split(";")[0].strip()
    if not media_type.startswith("audio/"):
        media_type = _MEDIA_TYPES[output_format]
    return body, media_type


def get_or_synthesize_speech(
    text: str, *, settings: dict[str, Any]
) -> tuple[bytes, str, bool, str]:
    cached = load_cached_recording(text, settings=settings)
    if cached is not None:
        audio, media_type = cached
        return audio, media_type, True, str(recording_path(text, settings=settings))
    audio, media_type = synthesize_speech(text, settings=settings)
    saved = save_recording(text, audio, settings=settings)
    return audio, media_type, False, saved
