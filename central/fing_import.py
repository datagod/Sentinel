"""Map Fing device exports into Sentinel Central friendly-device records."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

GENERIC_NAMES = {
    "",
    "?",
    "linux",
    "android",
    "unknown",
    "unnamed",
}

SOURCE_FING = "Imported from Fing"


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    hexpart = "".join(ch for ch in str(mac).upper() if ch in "0123456789ABCDEF")
    if len(hexpart) != 12:
        return str(mac).strip().upper() or None
    return ":".join(hexpart[i : i + 2] for i in range(0, 12, 2))


def _ms_to_utc(value: Any) -> str | None:
    if value in (None, "", "0", 0):
        return None
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if n <= 0 or n >= 2_000_000_000_000:  # skip bogus max-int timestamps
        return None
    if n > 10_000_000_000:
        n = n / 1000.0
    try:
        return datetime.fromtimestamp(n, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return None


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _hostname(record: dict[str, Any]) -> str | None:
    host = _clean(record.get("host_name"))
    if host and host.lower().endswith(".lan"):
        host = host[:-4]
    return host or None


def pick_name(record: dict[str, Any]) -> str:
    custom = _clean(record.get("customName"))
    if custom:
        return custom
    name = _clean(record.get("best_name"))
    if name and name.lower() not in GENERIC_NAMES and not name.lower().startswith("android"):
        return name
    model = _clean(record.get("best_model"))
    if model:
        return model
    dhcp = record.get("dhcp") if isinstance(record.get("dhcp"), dict) else {}
    dhcp_name = _clean(dhcp.get("name"))
    if dhcp_name:
        return dhcp_name
    host = _hostname(record)
    if host:
        return host
    return normalize_mac(record.get("mac_address")) or "unknown"


def device_from_fing(record: dict[str, Any]) -> dict[str, Any] | None:
    mac = normalize_mac(record.get("mac_address"))
    if not mac:
        return None
    ips = record.get("address_list") if isinstance(record.get("address_list"), list) else []
    ip_text = ", ".join(str(ip) for ip in ips if ip)
    return {
        "mac": mac,
        "name": pick_name(record),
        "device_type": _clean(record.get("customType")) or _clean(record.get("best_type")),
        "vendor": _clean(record.get("mac_vendor")) or _clean(record.get("best_make")),
        "model": _clean(record.get("best_model")),
        "os": " ".join(
            part
            for part in (_clean(record.get("best_os")), _clean(record.get("best_osver")))
            if part
        )
        or None,
        "hostname": _hostname(record),
        "ip_addresses": ip_text or None,
        "state": _clean(record.get("state")),
        "friendly": 1,
        "source": SOURCE_FING,
        "notes": SOURCE_FING,
        "first_seen": _ms_to_utc(record.get("firstseentime")),
        "last_seen": _ms_to_utc(record.get("lastseentime"))
        or _ms_to_utc(record.get("statechangetime")),
    }


def devices_from_fing(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        records = payload.get("devices") or payload.get("data") or [payload]
    elif isinstance(payload, list):
        records = payload
    else:
        raise ValueError("Fing export must be a JSON array of devices")
    devices: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        device = device_from_fing(record)
        if not device or device["mac"] in seen:
            continue
        seen.add(device["mac"])
        devices.append(device)
    return devices
