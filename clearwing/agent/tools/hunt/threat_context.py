"""Threat context tool: LLM-powered vulnerability hypothesis generation.

The model calls this when it reads code and wants expert context on what
typically goes wrong. If an oracle LLM is available, it gets a tailored
analysis of the specific code context. Falls back to a static knowledge
base keyed by pattern category.
"""

from __future__ import annotations

import logging

from pydantic import Field

from clearwing.llm import NativeToolSpec, ToolInputModel

from .sandbox import HunterContext

logger = logging.getLogger(__name__)

# Static knowledge base — used as system prompt context for the oracle LLM,
# and as fallback when no oracle is available.
THREAT_KNOWLEDGE: dict[str, str] = {
    "parser": (
        "Parsers processing untrusted input are where most memory corruption lives.\n"
        "Common failures:\n"
        "- Length fields trusted without bounds check → heap/stack overflow\n"
        "- Integer overflow in size calculations (length * element_size) → undersized allocation\n"
        "- Off-by-one in null terminator handling\n"
        "- State machine that doesn't reject malformed sequences → confused state\n"
        "- Nested structures with no depth limit → stack exhaustion\n"
        "- Type confusion: field says 'type A' but data is shaped as 'type B'\n"
        "Key question: where does the length/size come from, and is it validated BEFORE use?"
    ),
    "memory_allocator": (
        "Custom allocators and pool/slab managers:\n"
        "- Free list corruption: double-free creates a cycle → arbitrary write\n"
        "- Use-after-free: object returned to pool but pointer still live\n"
        "- Chunk header overwrite: overflow into allocator metadata\n"
        "- Integer overflow in round-up/alignment math → undersized chunk\n"
        "- Missing poisoning: freed memory retains sensitive data\n"
        "Key question: what separates the 'free' state from 'allocated' state, "
        "and can an attacker confuse the two?"
    ),
    "crypto_implementation": (
        "Cryptographic primitive implementations:\n"
        "- Timing side-channels: branches or memory access patterns dependent on secret\n"
        "- Nonce/IV reuse: counter reset, predictable random, static initialization\n"
        "- Missing MAC verification before decryption (decrypt-then-verify)\n"
        "- Padding oracle: different error paths for padding vs content failures\n"
        "- Key material not zeroed after use (remains on stack/heap)\n"
        "- Weak PRNG seeding: time-based, PID-based, or small entropy pool\n"
        "Key question: what is secret, and does any observable behavior (timing, "
        "errors, output length) depend on the secret value?"
    ),
    "crypto_verification": (
        "Signature/MAC/certificate verification logic:\n"
        "- Empty input bypass: loop over signatures never executes → returns 'valid'\n"
        "- Parameter validation: degenerate curve points (g=1, y=0) forge any signature\n"
        "- Type confusion: full IRI vs compact key in JSON-LD → wrong key used\n"
        "- Missing expiry/freshness check → replay captured signatures forever\n"
        "- Boolean initialization: failed=false + loop + return !failed → empty = pass\n"
        "Key question: what happens when the signature/MAC/cert sequence is EMPTY or "
        "contains degenerate values?"
    ),
    "auth_check": (
        "Authentication and authorization decision points:\n"
        "- Fail-open defaults: variable initialized to 'allowed', only set to 'denied' on match\n"
        "- TOCTOU: permission checked on one object, action performed on another\n"
        "- Confused deputy: checks presence of config section, not origin of the value\n"
        "- Short-circuit: first matching rule wins, ordering allows bypass\n"
        "- Type coercion: '0' == false == null in loose comparison languages\n"
        "- Missing resource scoping: checks 'can user access type X' not 'can user access THIS X'\n"
        "Key question: what is the DEFAULT outcome if the check doesn't explicitly pass/fail?"
    ),
    "file_path": (
        "File path construction from external input:\n"
        "- Directory traversal: '../' sequences escape intended directory\n"
        "- Backslash bypass: '..\\' not normalized on Unix → passes forward-slash checks\n"
        "- Null byte injection: 'file.txt\\x00.jpg' truncates at null in C but passes ext check\n"
        "- Symlink following: validated path points to symlink → actual target is elsewhere\n"
        "- Archive extraction (Zip Slip): entry name contains traversal sequences\n"
        "Key question: is the containment check (startsWith, normalize) applied AFTER "
        "all transformations (separator normalization, symlink resolution)?"
    ),
    "deserialization": (
        "Deserialization of untrusted data:\n"
        "- Object instantiation: pickle/Marshal/Java serialization → arbitrary constructors\n"
        "- Gadget chains: benign-looking classes combined → code execution\n"
        "- Type confusion: expected string, got object with __str__ override\n"
        "- Nested objects: no depth limit → resource exhaustion\n"
        "- Polymorphic dispatch: type discriminator from attacker → unexpected handler\n"
        "Key question: does the deserializer allow instantiation of arbitrary types, "
        "or is it restricted to a safe allowlist?"
    ),
    "command_execution": (
        "Shell/OS command construction:\n"
        "- Injection via metacharacters: ;, |, $(), ` ` in unsanitized input\n"
        "- Argument injection: --flag values that change command behavior\n"
        "- Environment variable manipulation: PATH, LD_PRELOAD, IFS\n"
        "- Partial quoting: quotes around part of command but not interpolated values\n"
        "- Array vs string: shell=True flattens list → interpretation as shell syntax\n"
        "Key question: does user input pass through a shell interpreter, or is it "
        "passed as a direct argv element?"
    ),
    "sql_query": (
        "SQL query construction:\n"
        "- String interpolation/concatenation: user input becomes SQL syntax\n"
        "- Second-order injection: value stored safely, used unsafely later\n"
        "- LIKE/REGEXP injection: % and _ as wildcards in pattern matching\n"
        "- Column/table name injection: identifiers can't use parameterized queries\n"
        "- Batch injection: stacked queries via semicolons (driver-dependent)\n"
        "Key question: is EVERY dynamic value parameterized, or are some (table names, "
        "ORDER BY, LIMIT) interpolated because they 'can't be parameterized'?"
    ),
    "integer_arithmetic": (
        "Integer arithmetic in security-critical paths:\n"
        "- Overflow in multiplication: count * size wraps → small allocation, large write\n"
        "- Signed/unsigned comparison: negative value becomes huge when cast to unsigned\n"
        "- Width truncation: 64-bit value assigned to 32-bit variable, high bits lost\n"
        "- Underflow: subtraction wraps to near-MAX → massive loop count or allocation\n"
        "- Division truncation: size/alignment rounds down → off-by-one slot\n"
        "Key question: can an attacker make the arithmetic result wrap, truncate, "
        "or go negative, and is the result used as a size, index, or loop bound?"
    ),
    "concurrency": (
        "Concurrent access and race conditions:\n"
        "- TOCTOU: check-then-act with window between check and action\n"
        "- Double-fetch: kernel reads user memory twice (value changes between reads)\n"
        "- Lock ordering: A→B vs B→A deadlock, or missing lock entirely\n"
        "- Static mutable state: global written from multiple threads without atomic\n"
        "- Signal handler: async-signal-unsafe operations in handler (malloc, printf)\n"
        "Key question: can an attacker control timing to hit the window between "
        "the check and the use, or between two reads of the same memory?"
    ),
    "web_request_handling": (
        "HTTP request processing in web frameworks:\n"
        "- Mass assignment: request body sets admin=true on model update\n"
        "- SSRF: user-controlled URL fetched server-side → access internal services\n"
        "- Header injection: CRLF in user value → inject Set-Cookie or Location\n"
        "- Template injection: user input rendered as template code (Jinja, ERB, Pug)\n"
        "- Missing CSRF token: state-changing action reachable via cross-origin form\n"
        "- Open redirect: unvalidated redirect_to parameter → phishing\n"
        "Key question: what user-controlled values reach response headers, template "
        "rendering, or outbound HTTP requests?"
    ),
    "device_register": (
        "Hardware/device register writes (virtio, MMIO, PCI config):\n"
        "- Post-activation write: config register modified after bounds validated at init\n"
        "- Missing state check: write handler doesn't verify device is in correct state\n"
        "- Endianness confusion: host vs device byte order on multi-byte registers\n"
        "- Bit-field overflow: value exceeds field width, clobbers adjacent fields\n"
        "- DMA from untrusted buffer: device reads from guest-controlled memory\n"
        "Key question: are register writes validated EVERY time, or only at "
        "initialization/activation?"
    ),
    "config_trust": (
        "Configuration value trust boundaries:\n"
        "- Section-exists vs value-origin: checks config section present, not where value came from\n"
        "- Environment variable override: env takes priority over safe config file\n"
        "- Default values: missing key falls through to unsafe default\n"
        "- Type coercion: string '0' vs boolean false vs null in config parsing\n"
        "- Precedence confusion: which config source wins when multiple define same key?\n"
        "Key question: can an attacker arrange for the config to exist (section present) "
        "while injecting a dangerous value from an untrusted source?"
    ),
}

# Aliases so the model can use natural language
_ALIASES: dict[str, str] = {
    "parsing": "parser",
    "parse": "parser",
    "buffer": "parser",
    "memcpy": "parser",
    "network_packet": "parser",
    "allocator": "memory_allocator",
    "malloc": "memory_allocator",
    "free": "memory_allocator",
    "pool": "memory_allocator",
    "slab": "memory_allocator",
    "heap": "memory_allocator",
    "crypto": "crypto_implementation",
    "encryption": "crypto_implementation",
    "aes": "crypto_implementation",
    "cipher": "crypto_implementation",
    "signature": "crypto_verification",
    "verify": "crypto_verification",
    "certificate": "crypto_verification",
    "mac": "crypto_verification",
    "jwt": "crypto_verification",
    "auth": "auth_check",
    "authorization": "auth_check",
    "permission": "auth_check",
    "access_control": "auth_check",
    "login": "auth_check",
    "path": "file_path",
    "file": "file_path",
    "directory": "file_path",
    "archive": "file_path",
    "zip": "file_path",
    "tar": "file_path",
    "deserialize": "deserialization",
    "pickle": "deserialization",
    "unmarshal": "deserialization",
    "yaml_load": "deserialization",
    "json_parse": "deserialization",
    "command": "command_execution",
    "shell": "command_execution",
    "exec": "command_execution",
    "system": "command_execution",
    "subprocess": "command_execution",
    "sql": "sql_query",
    "query": "sql_query",
    "database": "sql_query",
    "integer": "integer_arithmetic",
    "overflow": "integer_arithmetic",
    "arithmetic": "integer_arithmetic",
    "size_t": "integer_arithmetic",
    "cast": "integer_arithmetic",
    "race": "concurrency",
    "thread": "concurrency",
    "lock": "concurrency",
    "mutex": "concurrency",
    "atomic": "concurrency",
    "toctou": "concurrency",
    "web": "web_request_handling",
    "http": "web_request_handling",
    "request": "web_request_handling",
    "ssrf": "web_request_handling",
    "csrf": "web_request_handling",
    "template": "web_request_handling",
    "device": "device_register",
    "register": "device_register",
    "virtio": "device_register",
    "mmio": "device_register",
    "config": "config_trust",
    "configuration": "config_trust",
    "settings": "config_trust",
    "environment": "config_trust",
}

_ORACLE_SYSTEM = """You are a security vulnerability expert. Given a description of code
the researcher is looking at, return a focused list of:
1. The top 5 vulnerability patterns most likely to exist in this specific code
2. For each: the CWE, a one-line description, and what to check

Be specific to the code described — not generic advice. Focus on what an attacker
could actually exploit. Format as a numbered list, keep it under 200 words total.

Reference knowledge for common patterns:
{knowledge_context}"""


class ThreatContextInput(ToolInputModel):
    context: str = Field(
        description=(
            "Describe what you're looking at. Be specific: language, what the code does, "
            "what data it handles, what operations you see. "
            "Example: 'C function that reads a TLV length field from a network packet "
            "and passes it directly to memcpy into a fixed-size stack buffer'"
        )
    )


def _resolve_static(context: str) -> str | None:
    """Try to match context to a static knowledge entry."""
    key = context.lower().strip().replace(" ", "_").replace("-", "_")
    if key in THREAT_KNOWLEDGE:
        return THREAT_KNOWLEDGE[key]
    if key in _ALIASES:
        return THREAT_KNOWLEDGE[_ALIASES[key]]
    for alias, target in _ALIASES.items():
        if alias in key or key in alias:
            return THREAT_KNOWLEDGE[target]
    return None


def build_threat_context_tool(ctx: HunterContext) -> NativeToolSpec:

    async def get_threat_context(context: str, **_: object) -> str:
        # If we have an oracle LLM, use it for rich context-specific analysis
        if ctx.oracle_llm is not None:
            try:
                from clearwing.llm.native import ChatMessage

                # Build knowledge context from relevant static entries
                relevant = _resolve_static(context)
                knowledge_context = relevant or "\n\n".join(
                    f"## {k}\n{v}" for k, v in list(THREAT_KNOWLEDGE.items())[:5]
                )

                system = _ORACLE_SYSTEM.format(knowledge_context=knowledge_context)
                messages = [ChatMessage("user", context)]

                response = await ctx.oracle_llm.achat(
                    messages=messages,
                    system=system,
                    max_tokens=2000,
                )
                if response.text:
                    return response.text
            except Exception:
                logger.debug("Oracle LLM call failed, falling back to static", exc_info=True)

        # Fallback: static knowledge base
        static = _resolve_static(context)
        if static:
            return static

        # Last resort: return all pattern names
        available = sorted(THREAT_KNOWLEDGE.keys())
        return (
            f"No specific pattern matched for '{context[:80]}'. "
            f"Try being more specific, or use one of: {', '.join(available)}"
        )

    return NativeToolSpec(
        name="get_threat_context",
        description=(
            "Describe code you're looking at and get back targeted vulnerability hypotheses. "
            "Returns the most likely vulnerability patterns for your specific code context."
        ),
        schema=ThreatContextInput.model_json_schema(),
        handler=get_threat_context,
    )
