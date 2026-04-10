"""
utils.py
─────────────────────────────────────────────────────────────────────────────
BENSAM Framework — Shared utility helpers.
Kept in a separate module to avoid circular imports between core.py and audit.py.
"""

import ipaddress


def is_internal_ip(ip: str) -> bool:
    """
    Returns True if IP falls within any RFC-1918 private range:
        10.0.0.0/8
        172.16.0.0/12   (covers 172.16.x.x – 172.31.x.x, includes 172.24.x.x)
        192.168.0.0/16
    Works at home, office, lab — no config needed.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False