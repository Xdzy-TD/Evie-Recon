#!/usr/bin/env python3
"""SSL/TLS certificate inspection — retrieve and parse server certificates."""

import ssl
import socket
import datetime


def get_cert_info(host, port=443, timeout=5):
    """Connect via TLS and return certificate details.

    Args:
        host: Target hostname or IP.
        port: Target port (default 443).
        timeout: Connection timeout in seconds.

    Returns:
        A dict with certificate details, or None on failure.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=False)
                cipher = tls_sock.cipher()
                protocol = tls_sock.version()

                # If getpeercert returns empty dict (CERT_NONE), get DER cert
                if not cert:
                    der_cert = tls_sock.getpeercert(binary_form=True)
                    return _parse_der_cert(der_cert, cipher, protocol)

                return _parse_cert(cert, cipher, protocol)
    except Exception as e:
        return {"error": str(e)}


def _parse_cert(cert, cipher, protocol):
    """Parse a PEM-decoded certificate dict into a clean summary."""
    info = {}

    # Subject
    subject = dict(x[0] for x in cert.get("subject", ()))
    info["common_name"] = subject.get("commonName", "N/A")
    info["organization"] = subject.get("organizationName", "N/A")

    # Issuer
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    info["issuer"] = issuer.get("organizationName", "N/A")
    info["issuer_cn"] = issuer.get("commonName", "N/A")

    # Validity
    info["not_before"] = cert.get("notBefore", "N/A")
    info["not_after"] = cert.get("notAfter", "N/A")

    # Subject Alternative Names
    sans = cert.get("subjectAltName", ())
    info["san"] = [v for _, v in sans]

    # Serial number
    info["serial_number"] = cert.get("serialNumber", "N/A")

    # Connection details
    if cipher:
        info["cipher_suite"] = cipher[0]
        info["cipher_bits"] = cipher[2]
    info["tls_version"] = protocol

    return info


def _parse_der_cert(der_cert, cipher, protocol):
    """Minimal info when only the DER binary cert is available."""
    info = {
        "raw_cert_bytes": len(der_cert),
        "note": "Full parsing unavailable (CERT_NONE mode)",
    }
    if cipher:
        info["cipher_suite"] = cipher[0]
        info["cipher_bits"] = cipher[2]
    info["tls_version"] = protocol
    return info
