"""WiGLE API client (personal, non-commercial use under the WiGLE EULA)."""

from __future__ import annotations

import base64
import json
import math
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class WigleError(Exception):
    pass


def wigle_defaults(raw: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = dict(raw or {})
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "base_url": str(cfg.get("base_url") or "https://api.wigle.net").rstrip("/"),
        "api_name": str(cfg.get("api_name") or "").strip(),
        "api_token": str(cfg.get("api_token") or "").strip(),
    }


def public_wigle(settings: dict[str, Any]) -> dict[str, Any]:
    token = str(settings.get("api_token") or "")
    return {
        "enabled": bool(settings.get("enabled")),
        "base_url": str(settings.get("base_url") or "https://api.wigle.net").rstrip("/"),
        "api_name": str(settings.get("api_name") or ""),
        "has_api_token": bool(token),
    }


def _request(
    settings: dict[str, Any],
    path: str,
    *,
    query: dict[str, Any] | None = None,
    timeout: float = 20,
) -> dict[str, Any]:
    name = str(settings.get("api_name") or "").strip()
    token = str(settings.get("api_token") or "").strip()
    if not name or not token:
        raise WigleError("WiGLE API name and token are required")
    base = str(settings.get("base_url") or "https://api.wigle.net").rstrip("/")
    url = base + "/api/v2" + path
    if query:
        cleaned = {k: v for k, v in query.items() if v is not None and v != ""}
        if cleaned:
            url += "?" + urllib.parse.urlencode(cleaned)
    creds = base64.b64encode(f"{name}:{token}".encode("utf-8")).decode("ascii")
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Basic {creds}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300] if exc.fp else ""
        if exc.code in (401, 403):
            raise WigleError("WiGLE rejected the credentials (check API name and token)") from exc
        if exc.code == 429 or "too many queries" in detail.lower():
            raise WigleError("WiGLE daily query limit reached. Try again after 00:00 US/Pacific.") from exc
        raise WigleError(f"WiGLE HTTP {exc.code}: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise WigleError(f"WiGLE unreachable: {exc.reason}") from exc
    try:
        data = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise WigleError("WiGLE returned a non-JSON response") from exc
    if not isinstance(data, dict):
        raise WigleError("WiGLE returned an unexpected payload")
    if data.get("success") is False:
        raise WigleError(str(data.get("message") or f"WiGLE request failed ({status})"))
    return data


def test_connection(settings: dict[str, Any]) -> dict[str, Any]:
    """Call GET /api/v2/profile/user to verify credentials."""
    data = _request(settings, "/profile/user")
    user = data.get("user") if isinstance(data.get("user"), dict) else data
    userid = str(user.get("userid") or user.get("user") or "").strip()
    return {
        "ok": True,
        "userid": userid or "authenticated",
        "donate": user.get("donate"),
        "message": f"Signed in as {userid}" if userid else "WiGLE credentials work.",
    }


def _pick(data: dict[str, Any], *names: str) -> Any:
    for name in names:
        if data.get(name) not in (None, ""):
            return data[name]
    return None


def fetch_usage(settings: dict[str, Any]) -> dict[str, Any]:
    """Account stats from GET /api/v2/stats/user (and profile/user if present)."""
    stats = _request(settings, "/stats/user")
    nested = stats.get("statistics") if isinstance(stats.get("statistics"), dict) else {}
    profile: dict[str, Any] = {}
    try:
        raw_profile = _request(settings, "/profile/user")
        profile = raw_profile.get("user") if isinstance(raw_profile.get("user"), dict) else raw_profile
    except WigleError:
        profile = {}
    userid = str(
        _pick(nested, "userName", "userid", "user")
        or _pick(stats, "user", "userid")
        or _pick(profile, "userid", "user")
        or ""
    ).strip()
    return {
        "userid": userid,
        "rank": _pick(stats, "rank") or _pick(nested, "rank"),
        "month_rank": _pick(stats, "monthRank") or _pick(nested, "monthRank"),
        "discovered_wifi": _pick(nested, "discoveredWiFi") or _pick(stats, "discoveredWiFi"),
        "discovered_wifi_gps": _pick(nested, "discoveredWiFiGPS") or _pick(stats, "discoveredWiFiGPS"),
        "discovered_bt": _pick(nested, "discoveredBt") or _pick(stats, "discoveredBt"),
        "total_wifi_locations": _pick(nested, "totalWiFiLocations"),
        "month_count": _pick(nested, "eventMonthCount"),
        "prev_month_count": _pick(nested, "eventPrevMonthCount"),
        "first": _pick(nested, "first") or _pick(stats, "first"),
        "last": _pick(nested, "last") or _pick(stats, "last"),
    }


def _summarize_network(item: dict[str, Any]) -> dict[str, Any]:
    road = " ".join(
        part
        for part in (
            str(item.get("housenumber") or "").strip(),
            str(item.get("road") or "").strip(),
        )
        if part
    )
    place = ", ".join(
        part
        for part in (
            str(item.get("city") or "").strip(),
            str(item.get("region") or "").strip(),
            str(item.get("country") or "").strip(),
        )
        if part
    )
    return {
        "ssid": item.get("ssid") or "",
        "netid": item.get("netid") or "",
        "trilat": item.get("trilat"),
        "trilong": item.get("trilong"),
        "encryption": item.get("encryption") or "",
        "channel": item.get("channel"),
        "qos": item.get("qos"),
        "type": item.get("type") or "",
        "firsttime": item.get("firsttime") or "",
        "lasttime": item.get("lasttime") or "",
        "road": road,
        "place": place,
        "postalcode": item.get("postalcode") or "",
    }


def _box_for_miles(lat: float, lon: float, miles: float) -> dict[str, float]:
    dlat = miles / 69.172
    cos_lat = math.cos(math.radians(lat))
    dlon = miles / (69.172 * max(abs(cos_lat), 1e-6))
    return {
        "latrange1": round(lat - dlat, 6),
        "latrange2": round(lat + dlat, 6),
        "longrange1": round(lon - dlon, 6),
        "longrange2": round(lon + dlon, 6),
        "closestLat": lat,
        "closestLong": lon,
    }


def search_ssid(
    settings: dict[str, Any],
    ssid: str,
    *,
    lat: float | None = None,
    lon: float | None = None,
    results_per_page: int = 25,
) -> dict[str, Any]:
    """Look up an exact SSID within 2 miles of the sensor, then 10, then 100."""
    name = str(ssid or "").strip()
    if not name:
        raise WigleError("SSID is required")
    if lat is None or lon is None:
        raise WigleError("Sensor GPS is required for WiGLE SSID lookup")
    limit = max(1, min(int(results_per_page), 100))
    lat_f = float(lat)
    lon_f = float(lon)
    data: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    scope = "2 miles"
    for miles, label in ((2, "2 miles"), (10, "10 miles"), (100, "100 miles")):
        query: dict[str, Any] = {
            "ssid": name,
            "resultsPerPage": limit,
            **_box_for_miles(lat_f, lon_f, miles),
        }
        data = _request(settings, "/network/search", query=query)
        rows = [
            _summarize_network(item)
            for item in (data.get("results") or [])
            if isinstance(item, dict)
        ]
        scope = label
        if rows:
            break
    return {
        "ssid": name,
        "scope": scope,
        "total": data.get("totalResults", len(rows)),
        "results": rows,
    }
