"""TLS Inspection Tools — validate transport security and detect downgrade paths."""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from clearwing.agent.tooling import interrupt, tool

_KNOWN_SIG_OIDS: dict[str, str] = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

_PROTOCOL_VERSIONS: dict[str, tuple[int, int]] = {
    "SSLv3": (ssl.PROTOCOL_TLS_CLIENT, 0x0300),
    "TLSv1.0": (ssl.PROTOCOL_TLS_CLIENT, 0x0301),
    "TLSv1.1": (ssl.PROTOCOL_TLS_CLIENT, 0x0302),
    "TLSv1.2": (ssl.PROTOCOL_TLS_CLIENT, 0x0303),
}

_WEAK_CIPHERS = {"RC4", "DES", "3DES", "RC2", "IDEA", "SEED", "NULL", "EXPORT", "anon"}
_WEAK_KEY_EXCHANGE = {"RSA", "NULL", "EXPORT", "anon"}
_WEAK_HASHES = {"MD5", "SHA1"}


def _make_context(
    protocol_version: str | None = None,
    ciphers: str | None = None,
    verify: bool = True,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if protocol_version == "SSLv3":
        ctx.minimum_version = ssl.TLSVersion.SSLv3
        ctx.maximum_version = ssl.TLSVersion.SSLv3
    elif protocol_version == "TLSv1.0":
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
    elif protocol_version == "TLSv1.1":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    elif protocol_version == "TLSv1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif protocol_version == "TLSv1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if ciphers:
        ctx.set_ciphers(ciphers)
    return ctx


def _tls_connect(
    host: str,
    port: int,
    context: ssl.SSLContext,
    timeout: int = 10,
) -> tuple[ssl.SSLSocket, dict]:
    sock = socket.create_connection((host, port), timeout=timeout)
    ssock = context.wrap_socket(sock, server_hostname=host)
    cert = ssock.getpeercert() or {}
    return ssock, cert


def _parse_tag_length(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(data):
        raise ValueError("offset past end of data")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("truncated DER")
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80 == 0:
        length = length_byte
    else:
        num_bytes = length_byte & 0x7F
        if num_bytes == 0 or offset + num_bytes > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        offset += num_bytes
    return tag, offset, offset + length


def _decode_oid(data: bytes) -> str:
    if not data:
        return ""
    components = [str(data[0] // 40), str(data[0] % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            components.append(str(value))
            value = 0
    return ".".join(components)


def _parse_cert_der(der: bytes) -> dict:
    result: dict[str, Any] = {"key_bits": 0, "signature_algorithm": "unknown"}
    try:
        tag, start, end = _parse_tag_length(der, 0)
        if tag != 0x30:
            return result
        # tbsCertificate
        tag, tbs_start, tbs_end = _parse_tag_length(der, start)
        if tag != 0x30:
            return result

        pos = tbs_start
        # version (optional, context tag 0)
        if pos < tbs_end and der[pos] == 0xA0:
            _, _, ver_end = _parse_tag_length(der, pos)
            pos = ver_end
        # serialNumber
        tag, _, sn_end = _parse_tag_length(der, pos)
        pos = sn_end
        # signature algorithm
        tag, sig_start, sig_end = _parse_tag_length(der, pos)
        if tag == 0x30 and sig_start < sig_end:
            oid_tag, oid_start, oid_end = _parse_tag_length(der, sig_start)
            if oid_tag == 0x06:
                oid_str = _decode_oid(der[oid_start:oid_end])
                result["signature_algorithm"] = _KNOWN_SIG_OIDS.get(oid_str, oid_str)
        pos = sig_end
        # issuer
        _, _, issuer_end = _parse_tag_length(der, pos)
        pos = issuer_end
        # validity
        _, _, validity_end = _parse_tag_length(der, pos)
        pos = validity_end
        # subject
        _, _, subject_end = _parse_tag_length(der, pos)
        pos = subject_end
        # subjectPublicKeyInfo
        tag, spki_start, spki_end = _parse_tag_length(der, pos)
        if tag == 0x30 and spki_start < spki_end:
            # algorithm
            _, _, algo_end = _parse_tag_length(der, spki_start)
            # BIT STRING containing the public key
            bit_tag, bit_start, bit_end = _parse_tag_length(der, algo_end)
            if bit_tag == 0x03 and bit_start < bit_end:
                key_data_len = bit_end - bit_start - 1  # subtract unused-bits byte
                result["key_bits"] = key_data_len * 8
    except (ValueError, IndexError):
        pass
    return result


def _parse_cert_dict(cert_dict: dict) -> dict:
    def _flatten_dn(dn_tuples: tuple) -> dict:
        result = {}
        for rdn in dn_tuples:
            for attr_type, attr_value in rdn:
                result[attr_type] = attr_value
        return result

    subject = _flatten_dn(cert_dict.get("subject", ()))
    issuer = _flatten_dn(cert_dict.get("issuer", ()))
    sans = []
    for san_type, san_value in cert_dict.get("subjectAltName", ()):
        sans.append({"type": san_type, "value": san_value})

    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": cert_dict.get("notBefore", ""),
        "not_after": cert_dict.get("notAfter", ""),
        "serial_number": cert_dict.get("serialNumber", ""),
        "subject_alt_names": sans,
    }


def _fetch_security_headers(host: str, port: int, timeout: int = 10) -> dict:
    headers_of_interest = [
        "strict-transport-security",
        "public-key-pins",
        "public-key-pins-report-only",
        "expect-ct",
    ]
    result: dict[str, str] = {}
    try:
        url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
        req = urllib.request.Request(url, method="HEAD")
        resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
        for header in headers_of_interest:
            val = resp.getheader(header)
            if val:
                result[header] = val
    except Exception:
        pass
    return result


def _classify_cipher(cipher_name: str) -> str:
    upper = cipher_name.upper()
    if "3DES" in upper or "CBC3" in upper:
        return "weak"
    for weak in _WEAK_CIPHERS:
        if weak in upper:
            return "insecure" if weak in {"NULL", "EXPORT", "anon", "RC4", "DES"} else "weak"
    if "CBC" in upper and ("SHA" in upper and "SHA256" not in upper and "SHA384" not in upper):
        return "acceptable"
    if "GCM" in upper or "CHACHA" in upper or "CCM" in upper:
        return "strong"
    return "acceptable"


def _days_remaining(not_after_str: str) -> int | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            expiry = datetime.strptime(not_after_str, fmt).replace(tzinfo=timezone.utc)
            return (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            continue
    return None


def _key_strength_rating(key_bits: int) -> str:
    if key_bits >= 2048:
        return "strong"
    if key_bits >= 1024:
        return "acceptable"
    if key_bits > 0:
        return "weak"
    return "unknown"


@tool(
    name="scan_tls_config",
    description=(
        "Probe a host's TLS configuration: negotiated protocol version, "
        "cipher suite, certificate summary, and security headers."
    ),
)
def scan_tls_config(
    host: str,
    port: int = 443,
    timeout: int = 10,
) -> dict:
    """Probe TLS configuration of a host.

    Args:
        host: Target hostname (e.g. "example.com").
        port: TLS port (default 443).
        timeout: Connection timeout in seconds.

    Returns:
        Dict with negotiated protocol, cipher, certificate summary, and security headers.
    """
    ctx = _make_context(verify=False)
    try:
        ssock, cert_dict = _tls_connect(host, port, ctx, timeout)
    except Exception as e:
        return {"error": f"TLS connection failed: {e}"}

    try:
        protocol_version = ssock.version()
        cipher_info = ssock.cipher()
        cipher_name = cipher_info[0] if cipher_info else "unknown"
        cipher_bits = cipher_info[2] if cipher_info else 0

        cert_summary = _parse_cert_dict(cert_dict)

        try:
            der = ssock.getpeercert(binary_form=True)
            if der:
                der_info = _parse_cert_der(der)
                cert_summary["key_bits"] = der_info["key_bits"]
                cert_summary["signature_algorithm"] = der_info["signature_algorithm"]
                cert_summary["key_strength"] = _key_strength_rating(der_info["key_bits"])
        except Exception:
            pass
    finally:
        ssock.close()

    security_headers = _fetch_security_headers(host, port, timeout)

    return {
        "host": host,
        "port": port,
        "protocol_version": protocol_version,
        "cipher_suite": cipher_name,
        "cipher_bits": cipher_bits,
        "cipher_strength": _classify_cipher(cipher_name),
        "certificate": cert_summary,
        "security_headers": security_headers,
    }


@tool(
    name="enumerate_cipher_suites",
    description=(
        "Enumerate all cipher suites accepted by a TLS server using "
        "iterative exclusion. Returns the server's full cipher preference list "
        "with security ratings."
    ),
)
def enumerate_cipher_suites(
    host: str,
    port: int = 443,
    protocol: str = "TLSv1.2",
    timeout: int = 10,
) -> dict:
    """Enumerate accepted cipher suites via iterative exclusion.

    Args:
        host: Target hostname.
        port: TLS port.
        protocol: Protocol version to test ("TLSv1.2", "TLSv1.3", etc.).
        timeout: Connection timeout in seconds.

    Returns:
        Dict with ordered list of accepted ciphers and security assessment.
    """
    if not interrupt(
        f"About to enumerate cipher suites on {host}:{port} ({protocol}). "
        "This sends multiple TLS connections with iterative exclusion."
    ):
        return {"error": "User declined cipher enumeration."}

    accepted: list[dict] = []
    excluded: list[str] = []
    max_iterations = 100

    for _ in range(max_iterations):
        cipher_string = "ALL:COMPLEMENTOFALL"
        if excluded:
            cipher_string += ":" + ":".join(f"!{c}" for c in excluded)

        try:
            ctx = _make_context(protocol_version=protocol, ciphers=cipher_string, verify=False)
        except ssl.SSLError:
            break

        try:
            ssock, _ = _tls_connect(host, port, ctx, timeout)
            cipher_info = ssock.cipher()
            ssock.close()
        except (ssl.SSLError, OSError):
            break

        if not cipher_info:
            break

        cipher_name = cipher_info[0]
        if cipher_name in excluded:
            break

        accepted.append({
            "name": cipher_name,
            "bits": cipher_info[2],
            "protocol": cipher_info[1],
            "strength": _classify_cipher(cipher_name),
            "preference_order": len(accepted) + 1,
        })
        excluded.append(cipher_name)

    weak_count = sum(1 for c in accepted if c["strength"] in ("weak", "insecure"))
    strong_count = sum(1 for c in accepted if c["strength"] == "strong")

    if not accepted:
        assessment = f"No cipher suites accepted for {protocol}."
    elif weak_count > 0:
        assessment = (
            f"Server accepts {weak_count} weak/insecure cipher(s) out of {len(accepted)} total. "
            "Recommend disabling weak ciphers."
        )
    else:
        assessment = f"All {len(accepted)} accepted ciphers rated acceptable or strong ({strong_count} strong)."

    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "cipher_suites": accepted,
        "total_accepted": len(accepted),
        "strong_count": strong_count,
        "weak_count": weak_count,
        "assessment": assessment,
    }


_DOWNGRADE_PROTOCOLS: list[tuple[str, str, list[str]]] = [
    ("SSLv3", "SSLv3", ["POODLE (CVE-2014-3566)"]),
    ("TLSv1.0", "TLSv1.0", ["BEAST (CVE-2011-3389)", "Deprecated per RFC 8996"]),
    ("TLSv1.1", "TLSv1.1", ["Deprecated per RFC 8996"]),
]


@tool(
    name="test_tls_downgrade",
    description=(
        "Test for TLS protocol downgrade vulnerabilities by attempting "
        "connections with legacy protocols (SSLv3, TLS 1.0, TLS 1.1)."
    ),
)
def test_tls_downgrade(
    host: str,
    port: int = 443,
    timeout: int = 10,
) -> dict:
    """Test for TLS protocol downgrade vulnerabilities.

    Args:
        host: Target hostname.
        port: TLS port.
        timeout: Connection timeout in seconds.

    Returns:
        Dict with per-protocol results and vulnerability flags.
    """
    if not interrupt(
        f"About to test TLS downgrade on {host}:{port}. "
        "This attempts connections with legacy protocol versions."
    ):
        return {"error": "User declined downgrade test."}

    results: list[dict] = []
    vulnerabilities: list[str] = []

    for label, proto_version, vulns in _DOWNGRADE_PROTOCOLS:
        entry: dict[str, Any] = {
            "protocol": label,
            "accepted": False,
            "cipher": None,
            "known_vulnerabilities": vulns,
        }
        try:
            ctx = _make_context(protocol_version=proto_version, verify=False)
            ssock, _ = _tls_connect(host, port, ctx, timeout)
            cipher_info = ssock.cipher()
            ssock.close()
            entry["accepted"] = True
            entry["cipher"] = cipher_info[0] if cipher_info else "unknown"
            vulnerabilities.extend(vulns)
        except (ssl.SSLError, OSError, ValueError):
            entry["accepted"] = False
        results.append(entry)

    # Check for weak cipher families if TLS 1.2 is available
    weak_cipher_vulns: list[str] = []
    try:
        ctx = _make_context(protocol_version="TLSv1.2", verify=False)
        ssock, _ = _tls_connect(host, port, ctx, timeout)
        cipher_info = ssock.cipher()
        ssock.close()
        if cipher_info:
            cipher_upper = cipher_info[0].upper()
            if "EXPORT" in cipher_upper:
                weak_cipher_vulns.append("FREAK (CVE-2015-0204)")
            if "DHE" in cipher_upper and cipher_info[2] < 1024:
                weak_cipher_vulns.append("Logjam (CVE-2015-4000)")
            if "3DES" in cipher_upper or "DES-CBC3" in cipher_upper:
                weak_cipher_vulns.append("SWEET32 (CVE-2016-2183)")
    except (ssl.SSLError, OSError):
        pass

    vulnerabilities.extend(weak_cipher_vulns)

    any_legacy = any(r["accepted"] for r in results)
    if any_legacy:
        conclusion = (
            f"Server {host}:{port} accepts legacy protocol(s): "
            + ", ".join(r["protocol"] for r in results if r["accepted"])
            + ". Downgrade attacks may be possible."
        )
    else:
        conclusion = f"Server {host}:{port} correctly rejects all legacy protocols."

    return {
        "host": host,
        "port": port,
        "protocol_results": results,
        "weak_cipher_issues": weak_cipher_vulns,
        "all_vulnerabilities": list(set(vulnerabilities)),
        "downgrade_possible": any_legacy,
        "conclusion": conclusion,
    }


@tool(
    name="inspect_certificate",
    description=(
        "Deep inspection of a server's TLS certificate: key strength, "
        "signature algorithm, validity period, SANs, and trust assessment."
    ),
)
def inspect_certificate(
    host: str,
    port: int = 443,
    timeout: int = 10,
) -> dict:
    """Inspect a server's TLS certificate in detail.

    Args:
        host: Target hostname.
        port: TLS port.
        timeout: Connection timeout in seconds.

    Returns:
        Dict with certificate details, key strength rating, and trust assessment.
    """
    ctx = _make_context(verify=False)
    try:
        ssock, cert_dict = _tls_connect(host, port, ctx, timeout)
    except Exception as e:
        return {"error": f"TLS connection failed: {e}"}

    try:
        der = ssock.getpeercert(binary_form=True)
    finally:
        ssock.close()

    cert_info = _parse_cert_dict(cert_dict)
    der_info = _parse_cert_der(der) if der else {"key_bits": 0, "signature_algorithm": "unknown"}

    key_bits = der_info["key_bits"]
    sig_algo = der_info["signature_algorithm"]
    strength = _key_strength_rating(key_bits)

    days_left = _days_remaining(cert_info["not_after"])
    issues: list[str] = []

    if days_left is not None and days_left < 0:
        issues.append("Certificate has expired")
    elif days_left is not None and days_left < 30:
        issues.append(f"Certificate expires in {days_left} days")

    subject_cn = cert_info["subject"].get("commonName", "")
    issuer_cn = cert_info["issuer"].get("commonName", "")
    if subject_cn == issuer_cn and cert_info["subject"] == cert_info["issuer"]:
        issues.append("Self-signed certificate")

    sans = [s["value"] for s in cert_info["subject_alt_names"] if s["type"] == "DNS"]
    host_matched = False
    for san in sans:
        if san == host:
            host_matched = True
            break
        if san.startswith("*.") and host.endswith(san[1:]):
            host_matched = True
            break
    if not host_matched and subject_cn != host:
        if not any(
            san.startswith("*.") and host.endswith(san[1:])
            for san in [subject_cn]
            if san.startswith("*.")
        ):
            issues.append(f"Hostname mismatch: cert for {subject_cn}, connected to {host}")

    if strength == "weak":
        issues.append(f"Weak key size: {key_bits} bits")
    if "sha1" in sig_algo.lower():
        issues.append(f"Weak signature algorithm: {sig_algo}")

    trust = "trusted" if not issues else "issues_found"

    return {
        "host": host,
        "port": port,
        "certificate": cert_info,
        "key_bits": key_bits,
        "key_strength": strength,
        "signature_algorithm": sig_algo,
        "days_remaining": days_left,
        "issues": issues,
        "trust_assessment": trust,
    }


def get_tls_tools() -> list[Any]:
    """Return all TLS inspection tools."""
    return [scan_tls_config, enumerate_cipher_suites, test_tls_downgrade, inspect_certificate]
