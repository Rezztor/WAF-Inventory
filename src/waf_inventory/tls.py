"""HTTPS certificate for the console: self-signed on first start, or one signed by your internal CA via a CSR.

The folder holds key.pem + cert.pem (in use) and, while a CSR is out for signing, csr-key.pem. Private keys are
made here and never leave the folder.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WAF Inventory")])


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def _san(dns: list[str], ips: list[str]) -> x509.SubjectAlternativeName:
    return x509.SubjectAlternativeName([*map(x509.DNSName, dns), *(x509.IPAddress(ipaddress.ip_address(i)) for i in ips)])


def ensure_cert(folder: Path) -> tuple[Path, Path]:
    """Return (cert, key), creating a self-signed pair the first time."""
    cert, key = folder / "cert.pem", folder / "key.pem"
    if cert.exists() and key.exists():
        return cert, key
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    k = ec.generate_private_key(ec.SECP256R1())
    t = datetime.now(timezone.utc)
    c = (x509.CertificateBuilder().subject_name(NAME).issuer_name(NAME).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(t - timedelta(minutes=5))
         .not_valid_after(t + timedelta(days=825))
         .add_extension(_san(["localhost", socket.gethostname()], ["127.0.0.1"]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .sign(k, hashes.SHA256()))
    _write_key(key, k)
    cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    return cert, key


def fingerprint(cert: Path) -> str:
    return x509.load_pem_x509_certificate(cert.read_bytes()).fingerprint(hashes.SHA256()).hex(":").upper()


def make_csr(folder: Path, dns: list[str], ips: list[str]) -> bytes:
    """New key (kept as csr-key.pem until the signed certificate comes back) and a CSR for it."""
    if not dns and not ips:
        raise ValueError("give at least one DNS name or IP address the console is reached on")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    k = ec.generate_private_key(ec.SECP256R1())
    cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, (dns or ips)[0])])
    csr = x509.CertificateSigningRequestBuilder().subject_name(cn).add_extension(_san(dns, ips), critical=False).sign(k, hashes.SHA256())
    _write_key(folder / "csr-key.pem", k)
    return csr.public_bytes(serialization.Encoding.PEM)


def install_cert(folder: Path, chain_pem: bytes) -> str:
    """Install the CA-signed certificate (leaf first, then intermediates) for the pending CSR key. Returns its fingerprint."""
    pending = folder / "csr-key.pem"
    if not pending.exists():
        raise ValueError("no pending CSR: create one first")
    certs = x509.load_pem_x509_certificates(chain_pem)
    key = serialization.load_pem_private_key(pending.read_bytes(), None)
    if certs[0].public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError("the certificate does not match the CSR key; put the server certificate first in the file")
    if certs[0].not_valid_after_utc < datetime.now(timezone.utc):
        raise ValueError("the certificate has expired")
    (folder / "cert.pem").write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs))
    pending.replace(folder / "key.pem")
    return fingerprint(folder / "cert.pem")
