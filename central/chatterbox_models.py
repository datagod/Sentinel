"""Chatterbox TTS Server model identifiers and normalization."""

from __future__ import annotations

from typing import Any

CHATTERBOX_TTS_MODELS: tuple[dict[str, Any], ...] = (
    {
        "id": "chatterbox-turbo",
        "label": "Turbo",
        "description": "Fast English; supports [laugh], [sigh], [gasp], and other tags",
        "supports_paralinguistic_tags": True,
    },
    {
        "id": "chatterbox",
        "label": "Original",
        "description": "High-quality English with exaggeration and CFG tuning",
        "supports_paralinguistic_tags": False,
    },
    {
        "id": "chatterbox-multilingual",
        "label": "Multilingual",
        "description": "23 languages with zero-shot voice cloning",
        "supports_paralinguistic_tags": False,
    },
)

_VALID_TTS_MODEL_IDS = frozenset(m["id"] for m in CHATTERBOX_TTS_MODELS)
_TTS_MODEL_ALIASES = {
    "turbo": "chatterbox-turbo",
    "original": "chatterbox",
    "multilingual": "chatterbox-multilingual",
    "resembleai/chatterbox": "chatterbox",
    "resembleai/chatterbox-turbo": "chatterbox-turbo",
}
_MODEL_TYPE_TO_REPO_ID = {
    "turbo": "chatterbox-turbo",
    "original": "chatterbox",
    "multilingual": "chatterbox-multilingual",
}


def normalize_tts_model(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw in _VALID_TTS_MODEL_IDS:
        return raw
    return _TTS_MODEL_ALIASES.get(raw, "chatterbox-turbo")


def model_repo_id_from_info(info: dict[str, Any] | None) -> str:
    if not info:
        return "chatterbox-turbo"
    model_type = str(info.get("type") or "").strip().lower()
    return _MODEL_TYPE_TO_REPO_ID.get(model_type, "chatterbox-turbo")
