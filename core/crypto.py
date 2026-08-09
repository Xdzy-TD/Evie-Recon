#!/usr/bin/env python3
"""Cryptographic utilities for network fingerprinting and watermarking."""

import os
import socket
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_salt():
    """Generate cryptographic salt"""
    return os.urandom(32)


def generate_pepper():
    """Generate cryptographic pepper"""
    return os.urandom(32)


def generate_watermark(salt, watermark_text):
    """Generate secure watermark using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(watermark_text.encode())


def mathematical_fingerprint(ip, pepper, math_params):
    """Apply advanced mathematical fingerprinting"""
    # Convert IP to numerical representation
    ip_num = int.from_bytes(socket.inet_aton(ip), byteorder='big')

    # Apply cryptographic transformation
    cipher = Cipher(algorithms.AES(pepper), modes.CBC(b'\x00'*16),
                   backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad to 16 bytes (AES block size) for CBC mode
    ip_bytes = ip_num.to_bytes(4, byteorder='big').ljust(16, b'\x00')
    encrypted_ip = encryptor.update(ip_bytes) + encryptor.finalize()

    # Apply statistical transformations
    ip_array = np.frombuffer(encrypted_ip, dtype=np.uint8)
    mean = np.mean(ip_array)
    std_dev = np.std(ip_array)

    # Combine with mathematical parameters
    score = (mean * math_params['lambda']) + (std_dev * math_params['theta'])
    return score
