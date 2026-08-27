"""Cache Chatterbox TTS output under localrecordings, keyed by message and voice.

Matches frigate-tui: generate once, save atomically, reuse on later alerts/Speak tests.
"""

from __future__ import annotations

import array
import io
import re
import wave
from pathlib import Path
from typing import Any

from central.chatterbox_models import normalize_tts_model

_MAX_BASENAME_LEN = 120
_RECORDING_EXTENSIONS = {".wav", ".mp3", ".opus"}
_MEDIA_TYPES = {"wav": "audio/wav", "mp3": "audio/mpeg", "opus": "audio/opus"}


def resolve_recordings_dir(save_dir: str) -> Path:
    root = Path(save_dir).expanduser()
    if not root.is_absolute():
        root = (Path.cwd() / root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def voice_key_from_settings(settings: dict[str, Any]) -> str:
    if settings.get("voice_mode") == "clone":
        return str(settings.get("reference_audio_filename") or "clone").strip()
    return str(settings.get("predefined_voice_id") or "predefined").strip()


def _slug_part(value: str, *, max_len: int = _MAX_BASENAME_LEN) -> str:
    text = (value or "").strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "_", text).strip("_")
    if not text:
        return ""
    if len(text) > max_len:
        text = text[:max_len].rstrip("_")
    return text


def recording_filename(text: str, *, settings: dict[str, Any]) -> str:
    """Filesystem-safe name derived from message text (and voice for uniqueness)."""
    output_format = str(settings.get("output_format", "wav")).lower()
    if output_format not in _MEDIA_TYPES:
        output_format = "wav"
    message_slug = _slug_part(text) or "message"
    voice_slug = _slug_part(Path(voice_key_from_settings(settings)).stem, max_len=48)
    mode_slug = _slug_part(str(settings.get("delivery_mode") or "normal"), max_len=16)
    model_slug = _slug_part(normalize_tts_model(settings.get("tts_model")), max_len=24)
    parts = [message_slug]
    if voice_slug:
        parts.append(voice_slug)
    if mode_slug and mode_slug != "normal":
        parts.append(mode_slug)
    if model_slug and model_slug != "chatterbox_turbo":
        parts.append(model_slug)
    return f"{'__'.join(parts)}.{output_format}"


def recording_path(text: str, *, settings: dict[str, Any]) -> Path:
    root = resolve_recordings_dir(str(settings.get("cache_dir", "localrecordings")))
    return root / recording_filename(text, settings=settings)


def peak_normalize_wav(data: bytes, *, target_peak: float = 0.89) -> bytes:
    """Boost 16-bit WAV to near full scale so alerts are not whisper-quiet.

    Chatterbox clone voices often peak around -14 dBFS. The browser volume
    slider can only turn that down, so we raise the file itself to about -1 dBFS.
    """
    if not data or data[:4] != b"RIFF":
        return data
    try:
        with wave.open(io.BytesIO(data), "rb") as src:
            params = src.getparams()
            frames = src.readframes(src.getnframes())
    except wave.Error:
        return data
    if params.sampwidth != 2 or params.nchannels < 1 or not frames:
        return data
    samples = array.array("h")
    samples.frombytes(frames)
    if not samples:
        return data
    peak = max(abs(s) for s in samples)
    if peak < 64:
        return data
    target = max(1, min(32767, int(32767 * target_peak)))
    if peak >= int(target * 0.95):
        return data
    scale = target / peak
    for i, sample in enumerate(samples):
        value = int(sample * scale)
        if value > 32767:
            value = 32767
        elif value < -32768:
            value = -32768
        samples[i] = value
    out = io.BytesIO()
    with wave.open(out, "wb") as dst:
        dst.setparams(params)
        dst.writeframes(samples.tobytes())
    return out.getvalue()


def _write_audio_file(path: Path, audio: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(audio)
    tmp.replace(path)


def load_cached_recording(text: str, *, settings: dict[str, Any]) -> tuple[bytes, str] | None:
    path = recording_path(text, settings=settings)
    if not path.is_file() or path.stat().st_size <= 0:
        return None
    ext = path.suffix.lower().lstrip(".")
    data = path.read_bytes()
    if ext == "wav":
        loud = peak_normalize_wav(data)
        if loud != data:
            _write_audio_file(path, loud)
            data = loud
    return data, _MEDIA_TYPES.get(ext, "application/octet-stream")


def save_recording(text: str, audio: bytes, *, settings: dict[str, Any]) -> str:
    """Write audio to localrecordings atomically; return absolute path string."""
    path = recording_path(text, settings=settings)
    if path.suffix.lower() == ".wav":
        audio = peak_normalize_wav(audio)
    _write_audio_file(path, audio)
    return str(path)


def normalize_recordings_dir(root: str | Path) -> int:
    """Peak-normalize existing WAV cache files. Returns how many were rewritten."""
    folder = Path(root)
    if not folder.is_dir():
        return 0
    changed = 0
    for path in folder.glob("*.wav"):
        try:
            original = path.read_bytes()
        except OSError:
            continue
        loud = peak_normalize_wav(original)
        if loud != original:
            _write_audio_file(path, loud)
            changed += 1
    return changed


def _deslug(value: str) -> str:
    return (value or "").replace("_", " ").strip()


def parse_recording_basename(stem: str) -> tuple[str, str]:
    """Split cached filename stem into (message, voice) display strings."""
    text = (stem or "").strip()
    if "__" in text:
        msg_slug, voice_slug = text.rsplit("__", 1)
    else:
        msg_slug, voice_slug = text, ""
    return _deslug(msg_slug), _deslug(voice_slug)


def safe_recording_filename(name: str) -> str | None:
    """Reject path traversal; return basename if it looks like a cached recording."""
    base = Path(name).name
    if not base or base != name.strip() or base.startswith("."):
        return None
    suffix = Path(base).suffix.lower()
    if suffix not in _RECORDING_EXTENSIONS:
        return None
    stem = Path(base).stem
    if not stem or not re.match(r"^[\w][\w._-]*$", stem):
        return None
    return base


def media_type_for_filename(name: str) -> str:
    ext = Path(name).suffix.lower().lstrip(".")
    return _MEDIA_TYPES.get(ext, "application/octet-stream")


def recording_file_path(filename: str, *, cache_dir: str) -> Path | None:
    safe = safe_recording_filename(filename)
    if not safe:
        return None
    return resolve_recordings_dir(cache_dir) / safe


def delete_recording(filename: str, *, cache_dir: str) -> tuple[bool, str | None]:
    path = recording_file_path(filename, cache_dir=cache_dir)
    if path is None:
        return False, "invalid filename"
    if not path.is_file():
        return False, "not found"
    try:
        path.unlink()
        return True, None
    except OSError as e:
        return False, str(e)


def delete_recordings(filenames: list[str], *, cache_dir: str) -> dict[str, Any]:
    deleted: list[str] = []
    errors: dict[str, str] = {}
    seen: set[str] = set()
    for raw in filenames or []:
        name = str(raw or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        ok, err = delete_recording(name, cache_dir=cache_dir)
        if ok:
            deleted.append(name)
        elif err:
            errors[name] = err
    return {"deleted": deleted, "errors": errors}


def list_recordings(cache_dir: str) -> list[dict[str, Any]]:
    """Metadata for non-empty cached recordings, newest first."""
    root = resolve_recordings_dir(cache_dir)
    items: list[dict[str, Any]] = []
    if not root.is_dir():
        return items
    for entry in root.iterdir():
        if not entry.is_file():
            continue
        if entry.name.startswith(".") or entry.suffix.lower() == ".tmp":
            continue
        if entry.suffix.lower() not in _RECORDING_EXTENSIONS:
            continue
        try:
            stat = entry.stat()
        except OSError:
            continue
        if stat.st_size <= 0:
            continue
        message, voice = parse_recording_basename(entry.stem)
        items.append(
            {
                "filename": entry.name,
                "message": message,
                "voice": voice,
                "format": entry.suffix.lower().lstrip("."),
                "size_bytes": stat.st_size,
                "modified_at": stat.st_mtime,
            }
        )
    items.sort(key=lambda r: float(r.get("modified_at") or 0), reverse=True)
    return items
