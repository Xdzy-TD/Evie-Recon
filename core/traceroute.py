#!/usr/bin/env python3
"""
Traceroute — trace the network path to a target host.
Cross-platform: uses ``tracert`` on Windows and ``traceroute`` on Linux/macOS.
"""

import subprocess
import platform
import re


def traceroute(target, max_hops=30, timeout=3):
    """Trace the route to *target*.

    Args:
        target: Hostname or IP to trace.
        max_hops: Maximum number of hops.
        timeout: Per-hop timeout in seconds.

    Returns:
        A list of dicts, each with ``hop``, ``host``, ``ip``, and ``rtt_ms``.
    """
    system = platform.system().lower()

    try:
        if system == "windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w",
                   str(timeout * 1000), target]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w",
                   str(timeout), target]

        output = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL,
            timeout=max_hops * timeout + 10,
        ).decode(errors="replace")

        return _parse_output(output, system)
    except FileNotFoundError:
        return [{"error": "traceroute/tracert command not found"}]
    except subprocess.TimeoutExpired:
        return [{"error": "traceroute timed out"}]
    except Exception as e:
        return [{"error": str(e)}]


def _parse_output(output, system):
    """Parse raw traceroute/tracert output into structured hops."""
    hops = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Skip header lines
        if any(skip in line.lower() for skip in
               ["tracing route", "traceroute to", "over a maximum",
                "hops max", "trace complete"]):
            continue

        # Match hop lines: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
        # or: " 1  192.168.1.1  0.500 ms  0.400 ms  0.350 ms"
        hop_match = re.match(r'\s*(\d+)\s+(.+)', line)
        if not hop_match:
            continue

        hop_num = int(hop_match.group(1))
        rest = hop_match.group(2)

        # Extract IP addresses
        ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', rest)
        ip = ips[0] if ips else "*"

        # Extract RTT values (e.g., "1.234 ms" or "<1 ms")
        rtts = re.findall(r'(\d+\.?\d*)\s*ms', rest)
        if rtts:
            avg_rtt = sum(float(r) for r in rtts) / len(rtts)
            rtt_str = f"{avg_rtt:.1f} ms"
        elif "<1" in rest:
            rtt_str = "<1 ms"
            avg_rtt = 0.5
        elif "*" in rest and not ips:
            rtt_str = "* * *"
            avg_rtt = None
        else:
            rtt_str = "N/A"
            avg_rtt = None

        # Try to resolve hostname (avoid matching RTT values like "1.234 ms")
        host = ip
        host_match = re.findall(r'([a-zA-Z][\w\-]+(?:\.[\w\-]+)+\.[a-zA-Z]{2,})', rest)
        if host_match:
            host = host_match[0]

        hops.append({
            "hop": hop_num,
            "ip": ip,
            "host": host,
            "rtt": rtt_str,
            "rtt_avg_ms": avg_rtt,
        })

    return hops
