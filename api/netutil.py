"""
Shared network validation helpers for outbound requests.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urljoin, urlparse


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

    resolved = resolve_public_hostname(
        hostname,
        parsed.port or default_port,
        blocked_hosts=blocked_hosts,
        subject=subject,
    )

    return parsed.geturl()


def resolve_public_hostname(
    hostname: str,
    port: int | None,
    *,
    blocked_hosts: set[str] | None = None,
    subject: str = "Target",
) -> list[str]:
    normalized = (hostname or "").strip().lower()
    if not normalized:
        raise ValueError(f"{subject} must include a valid hostname.")

    blocked = blocked_hosts or set()
    if normalized in blocked or normalized.endswith(".local"):
        raise ValueError(f"{subject} host is not allowed.")

    try:
        resolved = sorted(
            {
                info[4][0]
                for info in socket.getaddrinfo(
                    normalized,
                    port,
                    proto=socket.IPPROTO_TCP,
                )
            }
        )
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

    return resolved


class _ValidatedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, validated_ip: str, **kwargs):
        super().__init__(host, **kwargs)
        self._validated_ip = validated_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._validated_ip, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()


class _ValidatedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, validated_ip: str, **kwargs):
        super().__init__(host, **kwargs)
        self._validated_ip = validated_ip

    def connect(self):
        sock = socket.create_connection(
            (self._validated_ip, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch_public_url(
    raw_url: str,
    *,
    allowed_schemes: set[str],
    blocked_hosts: set[str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
    max_redirects: int = 3,
    subject: str = "Target",
) -> tuple[str, str]:
    current_url = validate_public_url(
        raw_url,
        allowed_schemes=allowed_schemes,
        blocked_hosts=blocked_hosts,
        subject=subject,
    )
    request_headers = dict(headers or {})

    for _ in range(max_redirects + 1):
        parsed = urlparse(current_url)
        host = (parsed.hostname or "").strip()
        if not host:
            raise ValueError(f"{subject} must include a valid hostname.")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        validated_ip = resolve_public_hostname(
            host,
            port,
            blocked_hosts=blocked_hosts,
            subject=subject,
        )[0]
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"

        if parsed.scheme == "https":
            connection = _ValidatedHTTPSConnection(
                host,
                validated_ip,
                port=port,
                timeout=timeout,
                context=ssl.create_default_context(),
            )
        else:
            connection = _ValidatedHTTPConnection(
                host,
                validated_ip,
                port=port,
                timeout=timeout,
            )

        try:
            connection.request("GET", target, headers=request_headers)
            response = connection.getresponse()
            location = response.getheader("Location")

            if response.status in {301, 302, 303, 307, 308} and location:
                current_url = validate_public_url(
                    urljoin(current_url, location),
                    allowed_schemes=allowed_schemes,
                    blocked_hosts=blocked_hosts,
                    subject=subject,
                )
                response.read()
                continue

            body = response.read().decode("utf-8", errors="replace")
            return current_url, body
        finally:
            connection.close()

    raise ValueError(f"{subject} redirected too many times.")
