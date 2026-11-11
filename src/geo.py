"""Fictional site anchors and haversine distance.

Coordinates are invented so the rules have a distance to measure. They are not
a geolocation of the documentation IP ranges, and nothing here calls a GeoIP
service.
"""

from __future__ import annotations

import ipaddress
import math

# (name, latitude, longitude)
NORTHWIND = ("Northwind Campus", 45.0000, -120.0000)
HARBOR = ("Harbor Annex", 45.0400, -120.0000)
WESTPORT = ("Westport Lab", 45.0000, -70.0000)
OSTPORT = ("Ostport Relay", 45.0000, 30.0000)
EXTERNAL = ("External Relay", -10.0000, -120.0000)

_V4_CAMPUS = ipaddress.ip_network("192.0.2.0/24")
_V4_HARBOR = ipaddress.ip_network("198.51.100.0/24")
_V4_OTHER = ipaddress.ip_network("203.0.113.0/24")
_V6_DOC = ipaddress.ip_network("2001:db8::/32")


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometers."""
    radius = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(a))


def site_for_ip(ip: str) -> tuple[str, float, float]:
    """Map a generator address onto a fictional site.

    Scoring never calls this. Uploaded logs bring their own site and coordinates.
    """
    addr = ipaddress.ip_address(ip)
    if addr in _V4_CAMPUS or addr in _V6_DOC:
        return NORTHWIND
    if addr in _V4_HARBOR:
        return HARBOR
    if addr in _V4_OTHER:
        host = int(str(addr).rsplit(".", 1)[1])
        if 1 <= host <= 40:
            return WESTPORT
        if 80 <= host <= 129:
            return OSTPORT
        return EXTERNAL
    raise ValueError(f"{ip} is not in the fictional site map")
