#!/usr/bin/env python3
"""Banner grabbing — connect to open ports and read service banners."""

import socket


def grab_banner(ip, port, timeout=2):
    """Connect to a port and read the service banner.

    Args:
        ip: Target IP address.
        port: Target port number.
        timeout: Connection timeout in seconds.

    Returns:
        The banner string, or None if unavailable.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Some services (HTTP) need a probe to respond
        if port in (80, 8080, 8443):
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
        elif port == 443:
            # Skip raw banner grab on TLS ports; handled by ssl_recon
            sock.close()
            return None
        else:
            # Many services send a banner immediately on connect
            sock.sendall(b"\r\n")

        banner = sock.recv(1024).decode(errors="replace").strip()
        sock.close()
        return banner if banner else None
    except Exception:
        return None
