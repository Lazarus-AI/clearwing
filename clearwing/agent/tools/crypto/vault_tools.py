"""Vault Encryption Analysis Tools — parse and assess vault encryption security."""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from clearwing.agent.tooling import interrupt, tool

logger = logging.getLogger(__name__)

_AES_GCM_IV_BYTES = 12
_AES_GCM_TAG_BYTES = 16
_AES_256_KEY_BYTES = 32


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _base64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _base64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _detect_blob_format(data: str) -> str:
    data = data.strip()
    if not data:
        return "unknown"

    parts = data.split(".")
    if len(parts) == 5:
        try:
            _base64url_decode(parts[0])
            return "jwe_compact"
        except Exception:
            pass

    try:
        obj = json.loads(data)
        if isinstance(obj, dict) and "ciphertext" in obj:
            return "jwe_json"
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        if len(data) >= 2 and all(c in "0123456789abcdefABCDEF" for c in data):
            return "hex"
    except Exception:
        pass

    try:
        _base64url_decode(data)
        if len(data) > 20:
            return "base64"
    except Exception:
        pass

    return "unknown"


def _parse_jwe_compact(data: str) -> dict:
    parts = data.strip().split(".")
    if len(parts) != 5:
        raise ValueError(f"JWE compact requires 5 segments, got {len(parts)}")

    header_b64, ek_b64, iv_b64, ct_b64, tag_b64 = parts
    header_bytes = _base64url_decode(header_b64)
    header = json.loads(header_bytes)

    return {
        "header": header,
        "header_b64": header_b64,
        "encrypted_key": _base64url_decode(ek_b64) if ek_b64 else b"",
        "encrypted_key_b64": ek_b64,
        "iv": _base64url_decode(iv_b64),
        "iv_b64": iv_b64,
        "ciphertext": _base64url_decode(ct_b64),
        "ciphertext_b64": ct_b64,
        "tag": _base64url_decode(tag_b64),
        "tag_b64": tag_b64,
    }


def _parse_jwe_json(data: str) -> dict:
    obj = json.loads(data)
    header = {}
    header_b64 = obj.get("protected", "")
    if header_b64:
        header = json.loads(_base64url_decode(header_b64))

    if "header" in obj and isinstance(obj["header"], dict):
        header.update(obj["header"])

    return {
        "header": header,
        "header_b64": header_b64,
        "encrypted_key": _base64url_decode(obj.get("encrypted_key", "")),
        "encrypted_key_b64": obj.get("encrypted_key", ""),
        "iv": _base64url_decode(obj.get("iv", "")),
        "iv_b64": obj.get("iv", ""),
        "ciphertext": _base64url_decode(obj["ciphertext"]),
        "ciphertext_b64": obj["ciphertext"],
        "tag": _base64url_decode(obj.get("tag", "")),
        "tag_b64": obj.get("tag", ""),
    }


def _parse_binary_blob(data: bytes) -> dict:
    if len(data) < _AES_GCM_IV_BYTES + _AES_GCM_TAG_BYTES + 1:
        raise ValueError(f"Binary blob too short ({len(data)} bytes)")

    iv = data[:_AES_GCM_IV_BYTES]
    tag = data[-_AES_GCM_TAG_BYTES:]
    ciphertext = data[_AES_GCM_IV_BYTES:-_AES_GCM_TAG_BYTES]

    return {
        "header": {},
        "header_b64": "",
        "encrypted_key": b"",
        "encrypted_key_b64": "",
        "iv": iv,
        "iv_b64": _base64url_encode(iv),
        "ciphertext": ciphertext,
        "ciphertext_b64": _base64url_encode(ciphertext),
        "tag": tag,
        "tag_b64": _base64url_encode(tag),
    }


def _reassemble_jwe(
    header_b64: str, ek_b64: str, iv_b64: str, ct_b64: str, tag_b64: str
) -> str:
    return f"{header_b64}.{ek_b64}.{iv_b64}.{ct_b64}.{tag_b64}"


def _apply_modification(parsed: dict, mod_type: str) -> tuple[str, str]:
    iv = bytearray(parsed["iv"])
    ct = bytearray(parsed["ciphertext"])
    tag = bytearray(parsed["tag"])
    header_b64 = parsed.get("header_b64", "")
    ek_b64 = parsed.get("encrypted_key_b64", "")
    is_jwe = bool(header_b64)

    if mod_type == "bit_flip":
        if len(ct) > 0:
            ct[0] ^= 0x01
        desc = "Flipped bit 0 of first ciphertext byte"
    elif mod_type == "tag_truncation":
        tag = tag[:8]
        desc = "Truncated authentication tag to 8 bytes (64 bits)"
    elif mod_type == "tag_substitution":
        tag = bytearray(len(tag))
        desc = "Replaced authentication tag with all zeros"
    elif mod_type == "iv_zeroed":
        iv = bytearray(len(iv))
        desc = "Replaced IV/nonce with all zeros"
    elif mod_type == "ciphertext_truncation":
        if len(ct) > 16:
            ct = ct[:-16]
        desc = "Removed last 16 bytes of ciphertext"
    elif mod_type == "aad_removal":
        header_b64 = ""
        desc = "Removed protected header (AAD)"
    else:
        raise ValueError(f"Unknown modification: {mod_type}")

    if is_jwe:
        blob = _reassemble_jwe(
            header_b64,
            ek_b64,
            _base64url_encode(bytes(iv)),
            _base64url_encode(bytes(ct)),
            _base64url_encode(bytes(tag)),
        )
    else:
        blob = (bytes(iv) + bytes(ct) + bytes(tag)).hex()

    return blob, desc


def _detect_iv_reuse(encryption_ops: list[dict]) -> list[dict]:
    seen: dict[str, list[int]] = {}
    for i, op in enumerate(encryption_ops):
        iv = op.get("iv_hex", "")
        algo = op.get("algorithm", "")
        if iv:
            key = f"{algo}:{iv}"
            seen.setdefault(key, []).append(i)

    reuse = []
    for key, indices in seen.items():
        if len(indices) > 1:
            algo, iv_hex = key.split(":", 1)
            reuse.append({
                "iv_hex": iv_hex,
                "algorithm": algo,
                "operation_indices": indices,
                "count": len(indices),
            })
    return reuse


def _detect_key_reuse(
    captured_keys: list[dict], encryption_ops: list[dict]
) -> list[dict]:
    key_uses: dict[str, int] = {}
    for key_entry in captured_keys:
        hex_val = key_entry.get("hex", "")
        if hex_val and hex_val != "[non-extractable]":
            key_uses[hex_val] = key_uses.get(hex_val, 0) + 1

    for op in encryption_ops:
        key_hex = op.get("key_hex", "")
        if key_hex and key_hex != "[non-extractable]":
            key_uses[key_hex] = key_uses.get(key_hex, 0) + 1

    return [
        {"key_hex_preview": k[:16] + "...", "usage_count": v}
        for k, v in key_uses.items()
        if v > 1
    ]


_EXPECTED_1P_LAYERS = [
    ("derivation", {"deriveBits", "deriveKey"}, "Password → AUK derivation"),
    ("key_import", {"importKey"}, "Key import (AUK or keyset)"),
    ("unwrapping", {"unwrapKey"}, "Key unwrapping (keyset → vault key)"),
    ("encryption", {"encrypt", "decrypt"}, "Vault item encryption/decryption"),
]


def _map_to_1password_layers(hierarchy: list[dict]) -> dict:
    found: dict[str, list[int]] = {}
    for i, step in enumerate(hierarchy):
        op = step.get("operation", "")
        for layer_name, ops, _desc in _EXPECTED_1P_LAYERS:
            if op in ops:
                found.setdefault(layer_name, []).append(i)

    mapping = {}
    for layer_name, _ops, desc in _EXPECTED_1P_LAYERS:
        mapping[layer_name] = {
            "description": desc,
            "found": layer_name in found,
            "step_indices": found.get(layer_name, []),
        }
    return mapping


def _dispatch_parse(encrypted_data: str, fmt: str, format_hint: str) -> dict | None:
    if fmt == "jwe_compact":
        return _parse_jwe_compact(encrypted_data)
    if fmt == "jwe_json":
        return _parse_jwe_json(encrypted_data)
    if fmt == "hex":
        return _parse_binary_blob(bytes.fromhex(encrypted_data.strip()))
    if fmt == "base64":
        return _parse_binary_blob(_base64url_decode(encrypted_data.strip()))
    return None


def _check_blob_security(
    header: dict, iv: bytes, tag: bytes, ek: bytes
) -> tuple[list[str], list[str], str]:
    findings: list[str] = []
    recommendations: list[str] = []
    risk = "LOW"

    alg = header.get("alg", "")
    enc = header.get("enc", "")
    kid = header.get("kid", "")

    if len(iv) != _AES_GCM_IV_BYTES:
        findings.append(
            f"Non-standard IV length: {len(iv)} bytes (expected {_AES_GCM_IV_BYTES} for AES-GCM)"
        )
        recommendations.append("Use 12-byte (96-bit) nonces for AES-GCM")
        risk = "MEDIUM"

    if len(tag) < _AES_GCM_TAG_BYTES:
        findings.append(
            f"Truncated authentication tag: {len(tag)} bytes "
            f"(expected {_AES_GCM_TAG_BYTES} for full AES-GCM integrity)"
        )
        recommendations.append("Use full 128-bit (16-byte) authentication tags")
        risk = "HIGH"

    if enc and enc not in ("A256GCM", "A128GCM", "A192GCM"):
        findings.append(f"Unexpected encryption algorithm: {enc}")
    elif not enc and not header:
        findings.append("No algorithm identifier in blob — binary format")

    if header and not kid:
        findings.append("No key ID (kid) in header — cannot bind to specific key")
        recommendations.append("Include key ID for key management traceability")

    if alg == "dir":
        findings.append(
            "Direct key agreement (alg=dir) — no key wrapping layer. "
            "Key compromise directly exposes plaintext."
        )
        recommendations.append("Use key wrapping (AES-KW or RSA-OAEP) for defense in depth")
        if risk == "LOW":
            risk = "MEDIUM"

    if alg and alg != "dir" and len(ek) == 0:
        findings.append(f"Key management algorithm is {alg} but encrypted key is empty")
        if risk == "LOW":
            risk = "MEDIUM"

    if header.get("zip"):
        findings.append(f"Compression enabled before encryption (zip={header['zip']})")

    if not findings:
        findings.append("Blob structure appears standard for AES-GCM encryption")

    return findings, recommendations, risk


# ---------------------------------------------------------------------------
# Tool 1: parse_vault_blob
# ---------------------------------------------------------------------------


@tool(
    name="parse_vault_blob",
    description=(
        "Parse encrypted vault item structure to extract IV/nonce, ciphertext, "
        "authentication tag, key ID, and algorithm identifier. Identifies the "
        "encryption scheme without decryption. Supports JWE compact, JWE JSON, "
        "raw hex, and raw base64 formats."
    ),
)
def parse_vault_blob(
    encrypted_data: str,
    format_hint: str = "auto",
) -> dict:
    if not encrypted_data or not encrypted_data.strip():
        return {
            "error": "No encrypted data provided",
            "findings": ["Empty input — cannot parse"],
            "risk_level": "UNKNOWN",
        }

    fmt = format_hint if format_hint != "auto" else _detect_blob_format(encrypted_data)

    try:
        parsed = _dispatch_parse(encrypted_data, fmt, format_hint)
    except Exception as exc:
        return {
            "error": f"Parse failed: {exc}",
            "findings": [f"Failed to parse blob as {fmt}: {exc}"],
            "risk_level": "UNKNOWN",
        }

    if parsed is None:
        return {
            "error": f"Unable to detect format (hint={format_hint})",
            "findings": ["Blob format not recognized — provide format_hint"],
            "risk_level": "UNKNOWN",
        }

    header = parsed.get("header", {})
    iv = parsed["iv"]
    ct = parsed["ciphertext"]
    tag = parsed["tag"]
    ek = parsed["encrypted_key"]

    findings, recommendations, risk = _check_blob_security(header, iv, tag, ek)

    ct_hex = ct.hex()
    ct_display = ct_hex[:128] + "..." if len(ct_hex) > 128 else ct_hex

    return {
        "format": fmt if fmt != "unknown" else "binary",
        "algorithm": header.get("enc", "") or header.get("alg", "") or "unknown",
        "encryption": header.get("enc", ""),
        "key_management": header.get("alg", ""),
        "key_id": header.get("kid", ""),
        "iv_hex": iv.hex(),
        "iv_length_bytes": len(iv),
        "ciphertext_hex": ct_display,
        "ciphertext_length_bytes": len(ct),
        "tag_hex": tag.hex(),
        "tag_length_bytes": len(tag),
        "encrypted_key_hex": ek.hex() if ek else "",
        "encrypted_key_length_bytes": len(ek),
        "header": header,
        "findings": findings,
        "recommendations": recommendations,
        "risk_level": risk,
    }


# ---------------------------------------------------------------------------
# Tool 2: analyze_key_hierarchy
# ---------------------------------------------------------------------------


@tool(
    name="analyze_key_hierarchy",
    description=(
        "Analyze captured key hierarchy data from WebCrypto hooks to map the "
        "key derivation chain (AUK → personal keyset → vault keys → item keys). "
        "Takes the output dict from extract_key_hierarchy() and identifies "
        "extractable keys, missing wrapping layers, IV reuse, and other weaknesses."
    ),
)
def analyze_key_hierarchy(session_data: dict) -> dict:
    hierarchy = session_data.get("hierarchy", [])
    captured_keys = session_data.get("captured_keys", [])
    encryption_ops = session_data.get("encryption_operations", [])

    findings: list[str] = []
    recommendations: list[str] = []
    risk = "LOW"

    extractable_keys: list[dict] = []
    for step in hierarchy:
        op = step.get("operation", "")
        if op in ("importKey", "generateKey"):
            key_hex = step.get("output_key_hex", "[non-extractable]")
            if key_hex != "[non-extractable]":
                extractable_keys.append({
                    "step": step.get("step", 0),
                    "algorithm": step.get("algorithm", ""),
                    "key_hex_preview": key_hex[:16] + "..." if len(key_hex) > 16 else key_hex,
                })

    raw_captured = [
        k for k in captured_keys
        if k.get("hex", "[non-extractable]") != "[non-extractable]"
    ]

    if extractable_keys:
        findings.append(
            f"{len(extractable_keys)} key(s) marked extractable — raw key material "
            "accessible to JavaScript"
        )
        recommendations.append("Set extractable=false for all intermediate keys")
        risk = "HIGH"

    if raw_captured:
        findings.append(
            f"{len(raw_captured)} raw key(s) captured from WebCrypto log — "
            "key material was accessible"
        )
        if risk != "CRITICAL":
            risk = "HIGH"

    iv_reuse = _detect_iv_reuse(encryption_ops)
    if iv_reuse:
        findings.append(
            f"IV/nonce reuse detected in {len(iv_reuse)} case(s) — "
            "AES-GCM nonce reuse allows plaintext recovery via crib dragging "
            "and GHASH key recovery for tag forgery"
        )
        recommendations.append("Generate unique random nonces for every encryption operation")
        risk = "CRITICAL"

    key_reuse = _detect_key_reuse(captured_keys, encryption_ops)
    if key_reuse:
        findings.append(
            f"Key reuse detected: {len(key_reuse)} key(s) used in multiple contexts"
        )
        recommendations.append("Use distinct keys per vault or per item")
        if risk == "LOW":
            risk = "MEDIUM"

    wrapping_ops = [s for s in hierarchy if s.get("operation") in ("wrapKey", "unwrapKey")]
    wrapping_algos = list({s.get("algorithm", "") for s in wrapping_ops})
    derivation_algos = list({
        s.get("algorithm", "") for s in hierarchy
        if s.get("operation") in ("deriveBits", "deriveKey")
    })

    has_derivation = any(s.get("operation") in ("deriveBits", "deriveKey") for s in hierarchy)
    has_encryption = bool(encryption_ops) or any(
        s.get("operation") in ("encrypt", "decrypt") for s in hierarchy
    )
    if has_derivation and has_encryption and not wrapping_ops:
        findings.append(
            "No key wrapping operations (wrapKey/unwrapKey) detected between "
            "derivation and encryption — missing wrapping layer"
        )
        recommendations.append("Wrap derived keys before use with AES-KW or RSA-OAEP")
        if risk == "LOW":
            risk = "MEDIUM"

    layer_mapping = _map_to_1password_layers(hierarchy)
    missing_layers = [
        name for name, info in layer_mapping.items() if not info["found"]
    ]
    if missing_layers:
        findings.append(
            f"Expected 1Password layers not found: {', '.join(missing_layers)}"
        )

    key_chain = []
    for step in hierarchy:
        key_hex = step.get("output_key_hex", "[non-extractable]")
        key_chain.append({
            "step": step.get("step", 0),
            "operation": step.get("operation", ""),
            "algorithm": step.get("algorithm", ""),
            "extractable": key_hex != "[non-extractable]",
            "key_captured": bool(key_hex and key_hex != "[non-extractable]"),
        })

    if not findings:
        findings.append("Key hierarchy appears well-structured with no detected weaknesses")

    return {
        "hierarchy_depth": len(set(s.get("operation", "") for s in hierarchy)),
        "total_steps": len(hierarchy),
        "key_chain": key_chain,
        "captured_keys_count": len(raw_captured),
        "extractable_keys": extractable_keys,
        "non_extractable_keys_count": len(captured_keys) - len(raw_captured),
        "wrapping_operations": [
            {"step": s.get("step", 0), "operation": s.get("operation", ""), "algorithm": s.get("algorithm", "")}
            for s in wrapping_ops
        ],
        "wrapping_algorithms": wrapping_algos,
        "derivation_algorithms": derivation_algos,
        "encryption_key_reuse": key_reuse,
        "iv_reuse": iv_reuse,
        "missing_layers": missing_layers,
        "layer_mapping": layer_mapping,
        "findings": findings,
        "recommendations": recommendations,
        "risk_level": risk,
    }


# ---------------------------------------------------------------------------
# Tool 3: test_aead_integrity
# ---------------------------------------------------------------------------

_ALL_MODIFICATIONS = [
    "bit_flip",
    "tag_truncation",
    "tag_substitution",
    "iv_zeroed",
    "ciphertext_truncation",
    "aad_removal",
]

_SEVERITY_MAP = {
    "bit_flip": "CRITICAL",
    "tag_truncation": "HIGH",
    "tag_substitution": "CRITICAL",
    "iv_zeroed": "MEDIUM",
    "ciphertext_truncation": "HIGH",
    "aad_removal": "MEDIUM",
}


def _build_aead_payload(blob: str, request_template: str) -> dict:
    if request_template:
        return json.loads(request_template.replace("{{BLOB}}", blob))
    return {"enc": blob}


def _collect_baseline(http_post, url: str, blob: str, template: str, samples: int) -> dict:
    statuses, bodies, times = [], [], []
    for _ in range(samples):
        status, _hdrs, body, dur = http_post(url, _build_aead_payload(blob, template))
        statuses.append(status)
        bodies.append(body[:500])
        times.append(dur)
    return {"status": statuses[0], "body": bodies[0], "avg_ms": sum(times) / len(times)}


def _test_single_modification(
    http_post, url: str, parsed: dict, mod_type: str, template: str,
    samples: int, baseline: dict,
) -> tuple[dict, dict | None]:
    try:
        modified_blob, desc = _apply_modification(parsed, mod_type)
    except Exception as exc:
        return {"modification": mod_type, "description": f"Failed to apply: {exc}", "error": str(exc)}, None

    statuses, bodies, times = [], [], []
    for _ in range(samples):
        status, _hdrs, body, dur = http_post(url, _build_aead_payload(modified_blob, template))
        statuses.append(status)
        bodies.append(body[:500])
        times.append(dur)

    accepted = any(200 <= s < 300 for s in statuses)
    result = {
        "modification": mod_type,
        "description": desc,
        "server_status": statuses[0],
        "response_body": bodies[0],
        "response_ms": sum(times) / len(times),
        "accepted": accepted,
        "differs_from_original": statuses[0] != baseline["status"] or bodies[0] != baseline["body"],
    }

    vuln = None
    if accepted:
        sev = _SEVERITY_MAP.get(mod_type, "HIGH")
        vuln = {"modification": mod_type, "severity": sev, "description": f"Server accepted {desc} — {mod_type} bypass"}
    return result, vuln


def _escalate_risk(current: str, new: str) -> str:
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current


@tool(
    name="test_aead_integrity",
    description=(
        "Test AEAD implementation by sending modified ciphertexts to the server "
        "and observing responses. Tests for nonce reuse tolerance, tag verification "
        "bypass, associated data omission, and ciphertext malleability. "
        "Requires user approval before sending network requests."
    ),
)
def test_aead_integrity(
    encrypted_data: str,
    target: str,
    endpoint_path: str = "/api/v1/vault/items",
    modifications: str = "all",
    request_template: str = "",
    samples: int = 3,
) -> dict:
    mods = _ALL_MODIFICATIONS if modifications == "all" else [m.strip() for m in modifications.split(",")]

    if not interrupt(
        f"About to send {(len(mods) + 1) * samples} requests to {target}{endpoint_path} "
        f"testing {len(mods)} AEAD modifications"
    ):
        return {"error": "User declined AEAD integrity testing"}

    from clearwing.agent.tools.crypto.srp_tools import _http_post

    fmt = _detect_blob_format(encrypted_data)
    try:
        parsed = _dispatch_parse(encrypted_data, fmt, "auto")
    except Exception as exc:
        return {"error": f"Failed to parse encrypted data: {exc}"}
    if parsed is None:
        return {"error": f"Cannot parse encrypted data (format: {fmt})"}

    url = f"{target.rstrip('/')}{endpoint_path}"
    baseline = _collect_baseline(_http_post, url, encrypted_data, request_template, samples)

    results: list[dict] = []
    vulnerabilities: list[dict] = []
    worst_risk = "LOW"

    for mod_type in mods:
        result, vuln = _test_single_modification(
            _http_post, url, parsed, mod_type, request_template, samples, baseline,
        )
        results.append(result)
        if vuln:
            vulnerabilities.append(vuln)
            worst_risk = _escalate_risk(worst_risk, vuln["severity"])

    findings: list[str] = []
    recommendations: list[str] = []

    if vulnerabilities:
        findings.append(f"{len(vulnerabilities)} AEAD integrity bypass(es) detected")
        for v in vulnerabilities:
            findings.append(f"[{v['severity']}] {v['description']}")
        recommendations.append("Verify authentication tag before processing ciphertext")
        recommendations.append("Reject any modified ciphertext with a generic error")
    else:
        findings.append("All modified ciphertexts were rejected — AEAD integrity appears correct")

    return {
        "target": target,
        "original_blob_format": fmt,
        "modifications_tested": mods,
        "results": results,
        "baseline": baseline,
        "vulnerabilities": vulnerabilities,
        "findings": findings,
        "recommendations": recommendations,
        "risk_level": worst_risk,
    }


# ---------------------------------------------------------------------------
# Tool 4: key_wrap_analysis
# ---------------------------------------------------------------------------


def _compute_key_distinguishability(wrapped_keys: list[dict]) -> dict:
    lengths: list[int] = []
    for k in wrapped_keys:
        hex_val = k.get("wrapped_key_hex", "")
        if hex_val:
            lengths.append(len(bytes.fromhex(hex_val)))

    length_dist: dict[int, int] = {}
    for ln in lengths:
        length_dist[ln] = length_dist.get(ln, 0) + 1

    unique_lengths = len(length_dist)
    return {
        "distinguishable": unique_lengths > 1,
        "same_length_count": max(length_dist.values()) if length_dist else 0,
        "varying_length_count": sum(1 for v in length_dist.values() if v == 1),
        "length_distribution": {str(k): v for k, v in sorted(length_dist.items())},
        "details": (
            f"Wrapped keys have {unique_lengths} distinct length(s)"
            if lengths
            else "No wrapped key data to analyze"
        ),
    }


def _analyze_algo_group(
    algo: str, keys: list[dict]
) -> tuple[dict[str, Any], dict | None, dict | None]:
    algo_upper = algo.upper()
    key_sizes = []
    for k in keys:
        hex_val = k.get("wrapped_key_hex", "")
        if hex_val:
            key_sizes.append(len(bytes.fromhex(hex_val)))

    entry: dict[str, Any] = {
        "algorithm": algo,
        "count": len(keys),
        "key_sizes": sorted(set(key_sizes)),
    }

    if "KW" in algo_upper or "KEYWRAP" in algo_upper or algo_upper == "AES-KW":
        entry["is_deterministic"] = True
        entry["padding_type"] = "none (fixed 64-bit integrity check)"
        entry["oracle_risk"] = "LOW — AES-KW uses integrity check, not padding"

        size_anomalies = []
        for sz in key_sizes:
            if sz % 8 != 0:
                size_anomalies.append(f"{sz} bytes is not a multiple of 8")
            if sz < 24:
                size_anomalies.append(f"{sz} bytes is too small (min 24 = 16-byte key + 8-byte IV)")

        aes_kw = {
            "key_count": len(keys),
            "key_sizes": sorted(set(key_sizes)),
            "size_anomalies": size_anomalies,
            "integrity_check": "RFC 3394 64-bit integrity check value (0xA6A6...)",
        }
        return entry, aes_kw, None

    if "RSA" in algo_upper or "OAEP" in algo_upper:
        entry["is_deterministic"] = False
        entry["padding_type"] = "OAEP (randomized)"
        entry["oracle_risk"] = (
            "MEDIUM (theoretical) — RSA-OAEP is resistant to Bleichenbacher "
            "by design, but implementation flaws can create Manger-style oracles"
        )
        rsa_oaep = {
            "key_count": len(keys),
            "ciphertext_sizes": sorted(set(key_sizes)),
            "padding_scheme": "OAEP (randomized, Bleichenbacher-resistant)",
            "manger_attack_risk": (
                "Theoretical — requires observable error differences between "
                "valid/invalid OAEP padding during unwrap"
            ),
        }
        return entry, None, rsa_oaep

    entry["is_deterministic"] = None
    entry["padding_type"] = "unknown"
    entry["oracle_risk"] = "UNKNOWN — unrecognized wrapping algorithm"
    return entry, None, None


def _analyze_unwrap_ops(unwrap_operations: list[dict]) -> dict:
    return {
        "total_unwraps": len(unwrap_operations),
        "extractable_after_unwrap": sum(1 for op in unwrap_operations if op.get("extractable") is True),
        "non_extractable_after_unwrap": sum(1 for op in unwrap_operations if op.get("extractable") is False),
        "formats_used": list({op.get("format", "unknown") for op in unwrap_operations}),
    }


@tool(
    name="key_wrap_analysis",
    description=(
        "Analyze key wrapping scheme from captured wrapKey/unwrapKey operations. "
        "Identifies wrapping algorithm (AES-KW, RSA-OAEP), checks for wrapped "
        "key distinguishability, padding oracle potential, and extractability "
        "after unwrapping."
    ),
)
def key_wrap_analysis(
    wrapped_keys: list[dict],
    unwrap_operations: list[dict] | None = None,
) -> dict:
    if not wrapped_keys:
        return {
            "total_wrapped_keys": 0,
            "wrapping_algorithms": [],
            "algorithm_analysis": [],
            "key_distinguishability": {"distinguishable": False, "details": "No keys to analyze"},
            "aes_kw_analysis": None,
            "rsa_oaep_analysis": None,
            "unwrap_behavior": None,
            "findings": ["No wrapped keys provided — cannot analyze wrapping scheme"],
            "recommendations": ["Capture wrapKey/unwrapKey operations via WebCrypto hooks"],
            "risk_level": "UNKNOWN",
        }

    findings: list[str] = []
    recommendations: list[str] = []
    risk = "LOW"

    algo_groups: dict[str, list[dict]] = {}
    for key_entry in wrapped_keys:
        algo_groups.setdefault(key_entry.get("algorithm", "unknown"), []).append(key_entry)

    wrapping_algorithms = list(algo_groups.keys())
    key_distinguishability = _compute_key_distinguishability(wrapped_keys)

    if key_distinguishability["distinguishable"]:
        unique = len(key_distinguishability["length_distribution"])
        findings.append(
            f"Wrapped keys have {unique} distinct sizes — "
            "an observer can distinguish key types without decryption"
        )

    algorithm_analysis: list[dict] = []
    aes_kw_result = None
    rsa_oaep_result = None

    for algo, keys in algo_groups.items():
        entry, aes_kw, rsa_oaep = _analyze_algo_group(algo, keys)
        algorithm_analysis.append(entry)

        if aes_kw:
            aes_kw_result = aes_kw
            if aes_kw["size_anomalies"]:
                findings.append(f"AES-KW size anomalies: {'; '.join(aes_kw['size_anomalies'])}")
                recommendations.append("Ensure wrapped key sizes are multiples of 8 bytes and ≥ 24 bytes")
                risk = _escalate_risk(risk, "MEDIUM")
        elif rsa_oaep:
            rsa_oaep_result = rsa_oaep
        elif entry["is_deterministic"] is None:
            findings.append(f"Unrecognized wrapping algorithm: {algo}")

    if len(algo_groups) > 1:
        findings.append(f"Multiple wrapping algorithms in use: {', '.join(wrapping_algorithms)}")

    unwrap_behavior = None
    if unwrap_operations:
        unwrap_behavior = _analyze_unwrap_ops(unwrap_operations)
        if unwrap_behavior["extractable_after_unwrap"] > 0:
            findings.append(
                f"{unwrap_behavior['extractable_after_unwrap']} key(s) extractable after unwrapping — "
                "wrapping provides no effective protection against JS-level extraction"
            )
            recommendations.append("Set extractable=false when unwrapping keys")
            risk = "HIGH"

    if not findings:
        findings.append("Key wrapping scheme appears standard with no detected weaknesses")

    return {
        "total_wrapped_keys": len(wrapped_keys),
        "wrapping_algorithms": wrapping_algorithms,
        "algorithm_analysis": algorithm_analysis,
        "key_distinguishability": key_distinguishability,
        "aes_kw_analysis": aes_kw_result,
        "rsa_oaep_analysis": rsa_oaep_result,
        "unwrap_behavior": unwrap_behavior,
        "findings": findings,
        "recommendations": recommendations,
        "risk_level": risk,
    }


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def get_vault_tools() -> list:
    """Return all vault encryption analysis tools."""
    return [parse_vault_blob, analyze_key_hierarchy, test_aead_integrity, key_wrap_analysis]
