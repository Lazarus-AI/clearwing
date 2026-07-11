"""WebCrypto API instrumentation for capturing browser-side cryptographic operations."""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clearwing.agent.tooling import tool

logger = logging.getLogger(__name__)

_WEBCRYPTO_INSTRUMENT_JS = """
(function() {
  if (window.__clearwing_crypto_installed) return;

  var _origSubtle = {};
  var METHODS = [
    'encrypt','decrypt','sign','verify','digest',
    'generateKey','deriveKey','deriveBits',
    'importKey','exportKey','wrapKey','unwrapKey'
  ];
  for (var i = 0; i < METHODS.length; i++) {
    _origSubtle[METHODS[i]] = crypto.subtle[METHODS[i]].bind(crypto.subtle);
  }

  window.__clearwing_crypto_log = [];
  window.__clearwing_crypto_seq = 0;

  function bufToHex(buf, maxBytes) {
    maxBytes = maxBytes || 512;
    var arr = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer || buf);
    var len = Math.min(arr.length, maxBytes);
    var hex = '';
    for (var j = 0; j < len; j++) {
      hex += ('0' + arr[j].toString(16)).slice(-2);
    }
    return {
      hex: hex,
      length: arr.length,
      truncated: arr.length > maxBytes
    };
  }

  function serKey(key) {
    if (!key || typeof key !== 'object') return null;
    if (!(key instanceof CryptoKey)) return null;
    return {
      type: key.type,
      extractable: key.extractable,
      algorithm: JSON.parse(JSON.stringify(key.algorithm)),
      usages: Array.from(key.usages)
    };
  }

  function serAlgo(algo) {
    if (!algo) return null;
    if (typeof algo === 'string') return {name: algo};
    try {
      var o = {};
      for (var k in algo) {
        var v = algo[k];
        if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) {
          o[k] = bufToHex(v);
        } else if (v instanceof CryptoKey) {
          o[k] = serKey(v);
        } else {
          o[k] = v;
        }
      }
      return o;
    } catch(e) { return {name: String(algo)}; }
  }

  function serArg(val) {
    if (val === null || val === undefined) return null;
    if (typeof val === 'string') return val;
    if (typeof val === 'number' || typeof val === 'boolean') return val;
    if (val instanceof ArrayBuffer || ArrayBuffer.isView(val)) return bufToHex(val);
    if (val instanceof CryptoKey) return serKey(val);
    if (Array.isArray(val)) return val.map(function(x) { return typeof x === 'string' ? x : serArg(x); });
    return serAlgo(val);
  }

  function serArgs(method, args) {
    var a = Array.from(args);
    switch(method) {
      case 'encrypt': case 'decrypt':
        return {algorithm: serAlgo(a[0]), key: serKey(a[1]), data: serArg(a[2])};
      case 'sign': case 'verify':
        return {algorithm: serAlgo(a[0]), key: serKey(a[1]),
                signature_or_data: serArg(a[2]), data: a[3] !== undefined ? serArg(a[3]) : undefined};
      case 'digest':
        return {algorithm: serAlgo(a[0]), data: serArg(a[1])};
      case 'generateKey':
        return {algorithm: serAlgo(a[0]), extractable: a[1], usages: a[2]};
      case 'deriveKey':
        return {algorithm: serAlgo(a[0]), baseKey: serKey(a[1]),
                derivedAlgorithm: serAlgo(a[2]), extractable: a[3], usages: a[4]};
      case 'deriveBits':
        return {algorithm: serAlgo(a[0]), baseKey: serKey(a[1]), length: a[2]};
      case 'importKey':
        return {format: a[0], keyData: serArg(a[1]), algorithm: serAlgo(a[2]),
                extractable: a[3], usages: a[4]};
      case 'exportKey':
        return {format: a[0], key: serKey(a[1])};
      case 'wrapKey':
        return {format: a[0], key: serKey(a[1]),
                wrappingKey: serKey(a[2]), wrapAlgorithm: serAlgo(a[3])};
      case 'unwrapKey':
        return {format: a[0], wrappedKey: serArg(a[1]), unwrappingKey: serKey(a[2]),
                unwrapAlgorithm: serAlgo(a[3]), unwrappedKeyAlgorithm: serAlgo(a[4]),
                extractable: a[5], usages: a[6]};
      default:
        return {raw: a.map(serArg)};
    }
  }

  function serResult(method, result) {
    if (result instanceof ArrayBuffer || ArrayBuffer.isView(result)) return bufToHex(result);
    if (result instanceof CryptoKey) return serKey(result);
    if (result && result.publicKey) {
      return {publicKey: serKey(result.publicKey), privateKey: serKey(result.privateKey)};
    }
    return null;
  }

  METHODS.forEach(function(method) {
    crypto.subtle[method] = async function() {
      var args = arguments;
      var t0 = performance.now();
      var result = await _origSubtle[method].apply(null, args);
      var t1 = performance.now();
      var entry = {
        seq: window.__clearwing_crypto_seq++,
        method: method,
        timestamp: t0,
        durationMs: t1 - t0,
        algorithm: serArg(args[0]),
        args: serArgs(method, args),
        result: serResult(method, result),
        keyMaterial: null,
        stack: new Error().stack ? new Error().stack.split('\\n').slice(2, 6).join('\\n') : ''
      };
      if (result instanceof CryptoKey && result.extractable) {
        try {
          var raw = await _origSubtle.exportKey('raw', result);
          entry.keyMaterial = bufToHex(raw).hex;
        } catch(e) {
          try {
            var jwk = await _origSubtle.exportKey('jwk', result);
            entry.keyMaterial = JSON.stringify(jwk);
          } catch(e2) {}
        }
      }
      if (result instanceof ArrayBuffer || ArrayBuffer.isView(result)) {
        entry.keyMaterial = bufToHex(result).hex;
      }
      window.__clearwing_crypto_log.push(entry);
      if (window.__clearwing_crypto_log.length > 1000) {
        window.__clearwing_crypto_log = window.__clearwing_crypto_log.slice(-800);
      }
      return result;
    };
  });

  window.__clearwing_crypto_flush = function() {
    var entries = window.__clearwing_crypto_log.slice();
    window.__clearwing_crypto_log = [];
    return entries;
  };

  window.__clearwing_crypto_installed = true;
})();
"""

_SUBTLE_METHODS = [
    "encrypt", "decrypt", "sign", "verify", "digest",
    "generateKey", "deriveKey", "deriveBits",
    "importKey", "exportKey", "wrapKey", "unwrapKey",
]


@dataclass
class CryptoLogEntry:
    """A captured WebCrypto API operation."""

    id: int
    seq: int
    timestamp: str
    method: str
    algorithm: dict = field(default_factory=dict)
    args_summary: dict = field(default_factory=dict)
    result_summary: dict = field(default_factory=dict)
    key_material: str | None = None
    duration_ms: float = 0.0
    stack_trace: str = ""


class CryptoLog:
    """Thread-safe in-memory store for captured WebCrypto operations."""

    def __init__(self) -> None:
        self._entries: list[CryptoLogEntry] = []
        self._lock = threading.Lock()
        self._next_id = 1

    def add_batch(self, raw_entries: list[dict]) -> int:
        with self._lock:
            count = 0
            for raw in raw_entries:
                entry = CryptoLogEntry(
                    id=self._next_id,
                    seq=raw.get("seq", 0),
                    timestamp=datetime.now(tz=timezone.utc).isoformat(),
                    method=raw.get("method", "unknown"),
                    algorithm=raw.get("algorithm") or {},
                    args_summary=raw.get("args") or {},
                    result_summary=raw.get("result") or {},
                    key_material=raw.get("keyMaterial"),
                    duration_ms=raw.get("durationMs", 0.0),
                    stack_trace=(raw.get("stack") or "")[:500],
                )
                self._entries.append(entry)
                self._next_id += 1
                count += 1
            return count

    def get_all(
        self,
        method_filter: str | None = None,
        limit: int = 100,
    ) -> list[CryptoLogEntry]:
        with self._lock:
            results = list(self._entries)
        if method_filter:
            results = [e for e in results if e.method == method_filter]
        return results[-limit:]

    def get(self, entry_id: int) -> CryptoLogEntry | None:
        with self._lock:
            for e in self._entries:
                if e.id == entry_id:
                    return e
        return None

    def clear(self) -> int:
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            self._next_id = 1
            return count

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def export(self, path: str) -> None:
        with self._lock:
            data = [asdict(e) for e in self._entries]
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_crypto_logs: dict[str, CryptoLog] = {}
_hooks_installed: set[str] = set()
_context_hooks_installed = False


def _flush_js_log(tab_name: str) -> list[dict]:
    """Pull new entries from the browser-side log and ingest them."""
    from clearwing.agent.tools.recon.browser_tools import _get_page

    page = _get_page(tab_name)
    try:
        raw = page.evaluate(
            "window.__clearwing_crypto_flush"
            " ? window.__clearwing_crypto_flush()"
            " : []"
        )
    except Exception:
        raw = []

    if raw and tab_name in _crypto_logs:
        _crypto_logs[tab_name].add_batch(raw)
    return raw


# ---------------------------------------------------------------------------
# Agent tools
# ---------------------------------------------------------------------------


@tool
def install_webcrypto_hooks(tab_name: str = "default") -> dict:
    """Install WebCrypto API instrumentation hooks in a browser tab.

    Intercepts all crypto.subtle method calls (encrypt, decrypt, deriveBits,
    importKey, exportKey, generateKey, sign, verify, digest, deriveKey,
    wrapKey, unwrapKey) and logs arguments, results, key material, and timing.
    Hooks persist across navigations within the same browser context.

    Args:
        tab_name: Browser tab name to instrument.

    Returns:
        Dict with keys: success, tab_name, methods_hooked, message.
    """
    global _context_hooks_installed  # noqa: PLW0603

    try:
        from clearwing.agent.tools.recon.browser_tools import (
            _browser_state,
            _ensure_browser,
            _get_page,
        )

        _ensure_browser()
    except Exception as e:
        return {"success": False, "tab_name": tab_name, "error": str(e)}

    if _browser_state["context"] is None:
        _context_hooks_installed = False

    if not _context_hooks_installed:
        try:
            _browser_state["context"].add_init_script(_WEBCRYPTO_INSTRUMENT_JS)
            _context_hooks_installed = True
        except Exception as e:
            logger.warning("add_init_script failed: %s", e)

    page = _get_page(tab_name)
    try:
        page.evaluate(_WEBCRYPTO_INSTRUMENT_JS)
    except Exception as e:
        logger.warning("page.evaluate for webcrypto hooks failed: %s", e)

    if tab_name not in _crypto_logs:
        _crypto_logs[tab_name] = CryptoLog()
    _hooks_installed.add(tab_name)

    return {
        "success": True,
        "tab_name": tab_name,
        "methods_hooked": list(_SUBTLE_METHODS),
        "message": "WebCrypto hooks installed",
    }


@tool
def get_webcrypto_log(
    tab_name: str = "default",
    method_filter: str = "",
    limit: int = 50,
) -> dict:
    """Retrieve captured WebCrypto operations from an instrumented browser tab.

    Flushes new entries from the browser, then returns the requested slice
    of the Python-side log.

    Args:
        tab_name: Browser tab name.
        method_filter: Filter by SubtleCrypto method name (e.g. "deriveBits").
        limit: Maximum entries to return (default 50).

    Returns:
        Dict with keys: entries, total_count, returned_count.
    """
    if tab_name not in _hooks_installed:
        return {
            "entries": [],
            "total_count": 0,
            "returned_count": 0,
            "error": "WebCrypto hooks not installed. Call install_webcrypto_hooks first.",
        }

    _flush_js_log(tab_name)

    log = _crypto_logs[tab_name]
    entries = log.get_all(
        method_filter=method_filter or None,
        limit=limit,
    )

    serialized = [asdict(e) for e in entries]

    output = json.dumps(serialized, default=str)
    if len(output) > 50000:
        while len(json.dumps(serialized, default=str)) > 50000 and serialized:
            serialized.pop(0)

    return {
        "entries": serialized,
        "total_count": log.count,
        "returned_count": len(serialized),
    }


@tool
def clear_webcrypto_log(tab_name: str = "default") -> dict:
    """Clear the captured WebCrypto operation log for a browser tab.

    Args:
        tab_name: Browser tab name.

    Returns:
        Dict with keys: cleared_count, tab_name.
    """
    if tab_name not in _hooks_installed:
        return {"cleared_count": 0, "tab_name": tab_name, "error": "Hooks not installed."}

    count = _crypto_logs[tab_name].clear()

    from clearwing.agent.tools.recon.browser_tools import _get_page

    try:
        page = _get_page(tab_name)
        page.evaluate("window.__clearwing_crypto_log = []; window.__clearwing_crypto_seq = 0;")
    except Exception:
        pass

    return {"cleared_count": count, "tab_name": tab_name}


def _extract_algo_name(entry: CryptoLogEntry) -> str:
    algo = entry.algorithm
    if isinstance(algo, dict):
        return algo.get("name", algo.get("hex", ""))
    return ""


def _parse_kdf_from_derive_bits(args: dict) -> dict[str, Any] | None:
    args_algo = args.get("algorithm") or {}
    if not isinstance(args_algo, dict):
        return None
    if args_algo.get("name") not in ("PBKDF2", "HKDF"):
        return None
    salt_info = args_algo.get("salt") or {}
    kdf_entry: dict[str, Any] = {
        "algorithm": args_algo.get("name"),
        "hash": args_algo.get("hash"),
        "output_bits": args.get("length"),
    }
    if args_algo.get("name") == "PBKDF2":
        kdf_entry["iterations"] = args_algo.get("iterations")
    if isinstance(salt_info, dict):
        kdf_entry["salt_hex"] = salt_info.get("hex", "")
    elif isinstance(salt_info, str):
        kdf_entry["salt_hex"] = salt_info
    if args_algo.get("info"):
        info_val = args_algo["info"]
        kdf_entry["info_hex"] = info_val.get("hex", "") if isinstance(info_val, dict) else str(info_val)
    return kdf_entry


def _collect_import_key_materials(
    entry: CryptoLogEntry, algo_name: str, args: dict,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    if entry.key_material:
        results.append({
            "seq": entry.seq, "key_hex": entry.key_material,
            "algorithm": algo_name, "format": args.get("format"),
            "usages": (args.get("usages") or []), "from_method": "importKey",
        })
    key_data = args.get("keyData")
    if isinstance(key_data, dict) and key_data.get("hex"):
        results.append({
            "seq": entry.seq, "key_hex": key_data["hex"],
            "algorithm": algo_name, "format": args.get("format"),
            "usages": (args.get("usages") or []), "from_method": "importKey_input",
        })
    return results


@tool
def extract_srp_values(tab_name: str = "default") -> dict:
    """Parse the WebCrypto log to extract SRP-6a / key-derivation values.

    Identifies PBKDF2 deriveBits calls (password hashing), HKDF operations
    (key expansion), importKey calls, and AES-GCM encrypt/decrypt operations.

    Args:
        tab_name: Browser tab name.

    Returns:
        Dict with kdf parameters, derived keys, encryption ops, and timeline.
    """
    if tab_name not in _hooks_installed:
        return {"error": "WebCrypto hooks not installed. Call install_webcrypto_hooks first."}

    _flush_js_log(tab_name)
    entries = _crypto_logs[tab_name].get_all(limit=10000)

    kdf_info: list[dict[str, Any]] = []
    derived_keys: list[dict[str, Any]] = []
    encryption_ops: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []

    for entry in entries:
        algo_name = _extract_algo_name(entry)
        args = entry.args_summary

        timeline.append({
            "seq": entry.seq, "method": entry.method,
            "algorithm_name": algo_name, "timestamp": entry.timestamp,
        })

        if entry.method == "deriveBits":
            kdf = _parse_kdf_from_derive_bits(args)
            if kdf:
                kdf_info.append(kdf)
            if entry.key_material:
                derived_keys.append({
                    "seq": entry.seq, "key_hex": entry.key_material,
                    "algorithm": algo_name, "from_method": "deriveBits",
                })

        elif entry.method == "importKey":
            derived_keys.extend(_collect_import_key_materials(entry, algo_name, args))

        elif entry.method in ("encrypt", "decrypt"):
            args_algo = args.get("algorithm") or {}
            iv_info = args_algo.get("iv") or {}
            encryption_ops.append({
                "seq": entry.seq, "method": entry.method,
                "algorithm": args_algo.get("name", algo_name),
                "iv_hex": iv_info.get("hex", "") if isinstance(iv_info, dict) else str(iv_info),
                "data_length": (args.get("data") or {}).get("length"),
            })

        elif entry.method == "deriveKey" and entry.key_material:
            derived_keys.append({
                "seq": entry.seq, "key_hex": entry.key_material,
                "algorithm": algo_name, "from_method": "deriveKey",
            })

    return {
        "kdf": kdf_info,
        "derived_keys": derived_keys,
        "encryption_ops": encryption_ops,
        "timeline": timeline,
        "raw_entries_used": len(entries),
    }


@tool
def extract_key_hierarchy(tab_name: str = "default") -> dict:
    """Reconstruct the key derivation chain from captured WebCrypto operations.

    Traces the sequence of deriveBits, importKey, deriveKey, wrapKey,
    unwrapKey, and encrypt/decrypt calls to build a linearized key hierarchy.

    Args:
        tab_name: Browser tab name.

    Returns:
        Dict with hierarchy steps, captured keys, and encryption operations.
    """
    if tab_name not in _hooks_installed:
        return {"error": "WebCrypto hooks not installed. Call install_webcrypto_hooks first."}

    _flush_js_log(tab_name)
    entries = _crypto_logs[tab_name].get_all(limit=10000)

    hierarchy: list[dict[str, Any]] = []
    captured_keys: list[dict[str, Any]] = []
    encryption_ops: list[dict[str, Any]] = []
    step_num = 0

    for entry in entries:
        args = entry.args_summary
        algo_name = ""
        algo = entry.algorithm
        if isinstance(algo, dict):
            algo_name = algo.get("name", "")

        if entry.method in ("deriveBits", "deriveKey"):
            step_num += 1
            args_algo = args.get("algorithm") or {}
            hierarchy.append({
                "step": step_num,
                "operation": entry.method,
                "algorithm": args_algo.get("name", algo_name),
                "input": "baseKey",
                "output_key_hex": entry.key_material or "[non-extractable]",
                "output_length_bits": args.get("length"),
                "seq": entry.seq,
            })
            if entry.key_material:
                captured_keys.append({
                    "id": step_num,
                    "hex": entry.key_material,
                    "algorithm": algo_name,
                    "source": entry.method,
                    "seq": entry.seq,
                })

        elif entry.method == "importKey":
            step_num += 1
            key_data = args.get("keyData")
            input_hex = ""
            if isinstance(key_data, dict):
                input_hex = key_data.get("hex", "")
            hierarchy.append({
                "step": step_num,
                "operation": "importKey",
                "format": args.get("format"),
                "algorithm": algo_name,
                "input_key_hex": input_hex,
                "output_key_hex": entry.key_material or "[non-extractable]",
                "usages": args.get("usages"),
                "extractable": args.get("extractable"),
                "seq": entry.seq,
            })
            if entry.key_material:
                captured_keys.append({
                    "id": step_num,
                    "hex": entry.key_material,
                    "algorithm": algo_name,
                    "source": "importKey",
                    "seq": entry.seq,
                })

        elif entry.method in ("wrapKey", "unwrapKey"):
            step_num += 1
            hierarchy.append({
                "step": step_num,
                "operation": entry.method,
                "algorithm": algo_name,
                "format": args.get("format"),
                "output_key_hex": entry.key_material or "[non-extractable]",
                "seq": entry.seq,
            })
            if entry.key_material:
                captured_keys.append({
                    "id": step_num,
                    "hex": entry.key_material,
                    "algorithm": algo_name,
                    "source": entry.method,
                    "seq": entry.seq,
                })

        elif entry.method in ("encrypt", "decrypt"):
            args_algo = args.get("algorithm") or {}
            iv_info = args_algo.get("iv") or {}
            encryption_ops.append({
                "method": entry.method,
                "algorithm": args_algo.get("name", algo_name),
                "iv_hex": iv_info.get("hex", "") if isinstance(iv_info, dict) else str(iv_info),
                "data_length": (args.get("data") or {}).get("length"),
                "seq": entry.seq,
            })

        elif entry.method == "generateKey":
            step_num += 1
            hierarchy.append({
                "step": step_num,
                "operation": "generateKey",
                "algorithm": algo_name,
                "output_key_hex": entry.key_material or "[non-extractable]",
                "seq": entry.seq,
            })
            if entry.key_material:
                captured_keys.append({
                    "id": step_num,
                    "hex": entry.key_material,
                    "algorithm": algo_name,
                    "source": "generateKey",
                    "seq": entry.seq,
                })

    return {
        "hierarchy": hierarchy,
        "captured_keys": captured_keys,
        "encryption_operations": encryption_ops,
    }


def get_webcrypto_tools() -> list:
    """Return all WebCrypto instrumentation tools."""
    return [
        install_webcrypto_hooks,
        get_webcrypto_log,
        clear_webcrypto_log,
        extract_srp_values,
        extract_key_hierarchy,
    ]
