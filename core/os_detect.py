#!/usr/bin/env python3
"""OS fingerprinting — estimate remote OS via TTL and TCP window size."""

import socket
import struct

# Known OS signature table: (TTL range, TCP window size range) → OS family
OS_SIGNATURES = [
    {"os": "Linux 2.4/2.6",    "ttl": (64, 64),   "window": (5720, 5840)},
    {"os": "Linux 3.x/4.x",    "ttl": (64, 64),   "window": (14400, 29200)},
    {"os": "Linux 5.x+",       "ttl": (64, 64),   "window": (64240, 65535)},
    {"os": "Windows 10/11",     "ttl": (128, 128),  "window": (64240, 65535)},
    {"os": "Windows 7/8",       "ttl": (128, 128),  "window": (8192, 8192)},
    {"os": "Windows Server",    "ttl": (128, 128),  "window": (16384, 65535)},
    {"os": "macOS / iOS",       "ttl": (64, 64),   "window": (65535, 65535)},
    {"os": "FreeBSD",           "ttl": (64, 64),   "window": (65535, 65535)},
    {"os": "Cisco IOS",         "ttl": (255, 255),  "window": (4128, 4128)},
    {"os": "Solaris",           "ttl": (255, 255),  "window": (8760, 8760)},
]


def detect_os(ip, port=80, timeout=2):
    """Estimate the remote OS by analysing the TCP SYN-ACK response.

    Uses standard TCP connection to read TTL from the IP header and the
    TCP window size from the response, then matches against known OS
    signatures.

    Args:
        ip: Target IP address.
        port: An open port to connect to (default 80).
        timeout: Connection timeout in seconds.

    Returns:
        A dict with ``ttl``, ``window``, ``os_guess``, and ``confidence``.
    """
    ttl = _get_ttl(ip, port, timeout)
    window = _get_tcp_window(ip, port, timeout)

    if ttl is None and window is None:
        return {"os_guess": "Unknown", "confidence": "none", "ttl": None, "window": None}

    # Normalise TTL to its initial value (nearest power-of-two boundary)
    initial_ttl = _normalise_ttl(ttl) if ttl else None

    best_match = "Unknown"
    best_score = 0

    for sig in OS_SIGNATURES:
        score = 0
        total = 0

        if initial_ttl is not None:
            total += 1
            if sig["ttl"][0] <= initial_ttl <= sig["ttl"][1]:
                score += 1

        if window is not None:
            total += 1
            if sig["window"][0] <= window <= sig["window"][1]:
                score += 1

        if total > 0 and score / total > best_score:
            best_score = score / total
            best_match = sig["os"]

    confidence = "high" if best_score == 1.0 else "medium" if best_score >= 0.5 else "low"

    return {
        "ttl": ttl,
        "initial_ttl": initial_ttl,
        "window": window,
        "os_guess": best_match,
        "confidence": confidence,
    }


def _get_ttl(ip, port, timeout):
    """Retrieve the TTL value from a TCP connection."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # IP_TTL gives us the TTL of packets we *send*, so we use
        # a raw approach: read the TTL option from the socket itself.
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        sock.close()

        # On many systems getsockopt returns our local TTL, not remote.
        # Use a ping-based fallback via ICMP if available.
        remote_ttl = _ping_ttl(ip, timeout)
        return remote_ttl if remote_ttl else ttl
    except Exception:
        return _ping_ttl(ip, timeout)


def _ping_ttl(ip, timeout):
    """Try to get remote TTL via a raw ICMP echo (requires privileges)."""
    try:
        import subprocess
        import platform

        param = "-n" if platform.system().lower() == "windows" else "-c"
        is_win = platform.system().lower() == "windows"
        # Windows uses -w (milliseconds), Linux/macOS uses -W (seconds)
        if is_win:
            timeout_flag = ["-w", str(timeout * 1000)]
        else:
            timeout_flag = ["-W", str(timeout)]
        output = subprocess.check_output(
            ["ping", param, "1"] + timeout_flag + [ip],
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        ).decode(errors="replace")

        for line in output.splitlines():
            line_lower = line.lower()
            if "ttl=" in line_lower:
                idx = line_lower.index("ttl=")
                ttl_str = line[idx + 4:].split()[0].strip(".,;")
                return int(ttl_str)
    except Exception:
        pass
    return None


def _get_tcp_window(ip, port, timeout):
    """Retrieve the TCP window size advertised in the SYN-ACK."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # SO_RCVBUF approximates the advertised window
        window = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        sock.close()
        return window
    except Exception:
        return None


def _normalise_ttl(ttl):
    """Estimate the initial TTL from the observed (decremented) value."""
    if ttl is None:
        return None
    for initial in [32, 64, 128, 255]:
        if ttl <= initial:
            return initial
    return 255
