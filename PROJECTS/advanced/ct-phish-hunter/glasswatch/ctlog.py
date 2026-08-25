"""RFC 6962 Certificate Transparency log client.

Implements just enough of the protocol (rfc-editor.org/rfc/rfc6962) to
discover currently usable logs, ask a log how big it is (get-sth), pull a
range of new leaves (get-entries), and pull the certificate bytes back
out of each leaf. No third-party CT library: the wire format is a few
nested TLS presentation-language structures, and reading them by hand is
the point of an advanced-tier project.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

ENTRY_TYPE_X509 = 0
ENTRY_TYPE_PRECERT = 1


@dataclass(frozen=True)
class CTLog:
    operator: str
    description: str
    url: str  # always ends in "/", e.g. https://ct.cloudflare.com/logs/nimbus2026/


class ProtocolError(Exception):
    pass


def fetch_usable_logs(session: requests.Session | None = None) -> list[CTLog]:
    """Discover currently usable CT logs from Google's canonical log list.

    "Usable" means the operator is accepting submissions right now.
    Retired, frozen, and rejected logs are excluded: get-entries against
    those either 404s or returns a tree that stopped growing years ago,
    neither of which is useful for a real-time watcher.
    """
    session = session or requests.Session()
    resp = session.get(LOG_LIST_URL, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    logs: list[CTLog] = []
    for operator in data.get("operators", []):
        for log in operator.get("logs", []):
            if "usable" not in log.get("state", {}):
                continue
            logs.append(CTLog(
                operator=operator.get("name", "unknown"),
                description=log.get("description", ""),
                url=log["url"].rstrip("/") + "/",
            ))
    return logs


def get_sth(log: CTLog, session: requests.Session | None = None) -> int:
    """Fetch the log's current tree size (signed tree head, RFC 6962 §4.3).

    Signature verification is intentionally skipped: this project trusts
    TLS plus the fact that the log's URL came from Google's curated list,
    the same trust model the log list itself documents for monitors that
    are not doing full gossip/audit. See learn/04-CHALLENGES.md for what
    real STH signature verification would add.
    """
    session = session or requests.Session()
    resp = session.get(f"{log.url}ct/v1/get-sth", timeout=15)
    resp.raise_for_status()
    return int(resp.json()["tree_size"])


def get_entries(log: CTLog, start: int, end: int,
                 session: requests.Session | None = None) -> list[dict]:
    """Fetch leaves [start, end] inclusive (RFC 6962 §4.6).

    A log is free to return fewer entries than requested (most cap a
    single response around 1000-3000 leaves); the caller re-requests the
    remainder starting after the last index actually returned.
    """
    session = session or requests.Session()
    resp = session.get(
        f"{log.url}ct/v1/get-entries",
        params={"start": start, "end": end},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["entries"]


def _read_uint(buf: bytes, offset: int, size: int) -> tuple[int, int]:
    value = int.from_bytes(buf[offset:offset + size], "big")
    return value, offset + size


def _read_length_prefixed(buf: bytes, offset: int, prefix_size: int) -> tuple[bytes, int]:
    length, offset = _read_uint(buf, offset, prefix_size)
    data = buf[offset:offset + length]
    return data, offset + length


def parse_merkle_leaf(leaf_input_b64: str) -> tuple[int, int, bytes | None]:
    """Decode a MerkleTreeLeaf (RFC 6962 §3.4).

    Returns (entry_type, timestamp_ms, cert_der_or_none). For an
    x509_entry leaf, cert_der is the complete leaf certificate. For a
    precert_entry leaf, cert_der is always None: the leaf only carries
    the certificate's bare TBS bytes (no outer Certificate wrapper or
    signature), which `cryptography` refuses to load on their own. The
    real pre-certificate lives in the entry's extra_data instead, see
    parse_precert_extra_data below.
    """
    buf = base64.b64decode(leaf_input_b64)
    offset = 0

    version, offset = _read_uint(buf, offset, 1)
    leaf_type, offset = _read_uint(buf, offset, 1)
    if version != 0 or leaf_type != 0:
        raise ProtocolError(f"unsupported MerkleTreeLeaf version={version} leaf_type={leaf_type}")

    timestamp_ms, offset = _read_uint(buf, offset, 8)
    entry_type, offset = _read_uint(buf, offset, 2)

    if entry_type == ENTRY_TYPE_X509:
        cert_der, _ = _read_length_prefixed(buf, offset, 3)
        return entry_type, timestamp_ms, cert_der

    if entry_type == ENTRY_TYPE_PRECERT:
        return entry_type, timestamp_ms, None

    raise ProtocolError(f"unknown LogEntryType {entry_type}")


def parse_precert_extra_data(extra_data_b64: str) -> bytes:
    """Pull the pre-certificate DER out of a precert entry's extra_data
    (PrecertChainEntry, RFC 6962 §3.4).

    The pre-certificate is a structurally complete X.509 certificate: it
    carries the real SubjectAltName extension and a critical CT "poison"
    extension in place of where the final signature would be verified
    against, so `cryptography` parses it fine even though it would never
    pass signature validation as a real leaf certificate.
    """
    buf = base64.b64decode(extra_data_b64)
    pre_certificate, _ = _read_length_prefixed(buf, 0, 3)
    return pre_certificate


def load_certificate(der: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der, default_backend())


def extract_dns_names(cert: x509.Certificate) -> list[str]:
    """Pull every DNS SAN out of a certificate.

    Falls back to the Subject Common Name only if there is no SAN at
    all, which covers the handful of legacy certs still floating around
    that predate the SAN requirement (CA/Browser Forum deprecated
    CN-only certs in 2017).
    """
    names: set[str] = set()
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names.update(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass

    if not names:
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            names.add(str(attr.value))

    return sorted(n.lower().strip(".") for n in names if n)


def leaf_to_domains(entry: dict) -> list[str]:
    """End-to-end: one get-entries() list item -> the DNS names in its cert.

    Returns [] rather than raising on a malformed entry. A live log
    always has a handful of oddly-shaped certificates in it; one bad
    leaf should not take down a streaming scan.
    """
    try:
        entry_type, _, cert_der = parse_merkle_leaf(entry["leaf_input"])
        if entry_type == ENTRY_TYPE_PRECERT:
            cert_der = parse_precert_extra_data(entry["extra_data"])
        if cert_der is None:
            return []
        cert = load_certificate(cert_der)
        return extract_dns_names(cert)
    except Exception:  # noqa: BLE001 - one bad leaf must not kill a long-running stream
        return []
