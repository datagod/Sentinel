"""Estimate device range from Wi-Fi RSSI and place it around the sensor GPS."""

from __future__ import annotations

import hashlib
import math
from typing import Any

# RSSI (dBm) expected at 1 meter, and path-loss exponent n.
# 2.4 GHz probes travel farther; 5 GHz falls off faster.
_BAND_MODEL = {
    "5": (-35.0, 2.7),
    "2.4": (-30.0, 2.5),
}

MIN_RANGE_M = 2.0
MAX_RANGE_M = 600.0


def rssi_to_meters(signal: Any, band: str | None = None) -> float | None:
    if signal is None or signal == "":
        return None
    try:
        rssi = float(signal)
    except (TypeError, ValueError):
        return None
    band_l = str(band or "").lower()
    one_meter_rssi, exponent = _BAND_MODEL["5"] if "5" in band_l else _BAND_MODEL["2.4"]
    distance = 10 ** ((one_meter_rssi - rssi) / (10.0 * exponent))
    return round(max(MIN_RANGE_M, min(distance, MAX_RANGE_M)), 1)


def meters_to_feet(meters: float) -> float:
    return round(meters * 3.28084, 0)


def mac_bearing_radians(mac: str) -> float:
    digest = hashlib.sha256(str(mac).encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") / 0xFFFFFFFF * 2 * math.pi


def offset_coordinates(
    lat: float, lon: float, meters: float, bearing_rad: float
) -> tuple[float, float]:
    north = meters * math.cos(bearing_rad)
    east = meters * math.sin(bearing_rad)
    dlat = north / 111_320.0
    cos_lat = math.cos(math.radians(lat))
    if abs(cos_lat) < 1e-6:
        cos_lat = 1e-6
    dlon = east / (111_320.0 * cos_lat)
    return lat + dlat, lon + dlon


def plot_device(
    center_lat: float,
    center_lon: float,
    *,
    mac: str,
    signal: Any,
    band: str | None,
) -> dict[str, float] | None:
    distance_m = rssi_to_meters(signal, band)
    if distance_m is None:
        return None
    bearing = mac_bearing_radians(mac)
    lat, lon = offset_coordinates(center_lat, center_lon, distance_m, bearing)
    return {
        "lat": round(lat, 7),
        "lon": round(lon, 7),
        "distance_m": distance_m,
        "distance_ft": meters_to_feet(distance_m),
        "bearing_deg": round(math.degrees(bearing) % 360, 1),
    }
