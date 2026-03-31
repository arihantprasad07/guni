"""
Shared network validation helpers for outbound requests.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def validate_public_url(
    raw_url: str,
    *,
    allowed_schemes: set[str],
    blocked_hosts: set[str] | None = None,
    default_port: int | None = None,
    subject: str = "Target",
) -> str:
    parsed = urlparse((raw_url or "").strip())
    if parsed.scheme not in allowed_schemes:
        allowed = " and ".join(sorted(allowed_schemes))
        raise ValueError(f"Only {allowed} URLs are allowed.")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValueError(f"{subject} must include a valid hostname.")

    blocked = blocked_hosts or set()
    if hostname in blocked or hostname.endswith(".local"):
        raise ValueError(f"{subject} host is not allowed.")

    try:
        resolved = {
            info[4][0]
            for info in socket.getaddrinfo(
                hostname,
                parsed.port or default_port,
                proto=socket.IPPROTO_TCP,
            )
        }
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve {subject.lower()} hostname.") from exc

    for ip_text in resolved:
        ip_obj = ipaddress.ip_address(ip_text)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise ValueError(f"{subject} resolves to a non-public IP address.")

    return parsed.geturl()
