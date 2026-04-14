"""Guardrail patterns for prompt injection and dangerous command detection."""

import re
from dataclasses import dataclass, field


@dataclass
class GuardrailResult:
    """Result of a guardrail check."""

    passed: bool
    reason: str = ""
    severity: str = "info"  # "info", "warning", "critical"


# ---------------------------------------------------------------------------
# Prompt injection patterns (50+)
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: list[re.Pattern] = [
    # ---- Role injection ----
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?prior\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?above\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+everything\s+(above|before)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+your\s+(instructions|programming|training|rules)", re.IGNORECASE),
    re.compile(r"forget\s+your\s+(instructions|programming|training|rules|guidelines)", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all)\s+(you|that)", re.IGNORECASE),
    re.compile(r"override\s+(your|all|the|previous)\s+(instructions|programming|rules|settings)", re.IGNORECASE),
    re.compile(r"new\s+instructions\s*:", re.IGNORECASE),
    re.compile(r"updated\s+instructions\s*:", re.IGNORECASE),
    re.compile(r"revised\s+instructions\s*:", re.IGNORECASE),
    re.compile(r"system\s*:\s*.{0,5}(you are|you must|ignore|forget|override)", re.IGNORECASE),
    re.compile(r"^system\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"you\s+are\s+now\s+(a|an|the|my)\s+", re.IGNORECASE),
    re.compile(r"from\s+now\s+on\s+you\s+(are|will|must|should)", re.IGNORECASE),
    re.compile(r"your\s+new\s+(role|purpose|instructions|directive)", re.IGNORECASE),
    re.compile(r"switch\s+to\s+(a\s+)?new\s+(role|mode|persona)", re.IGNORECASE),
    re.compile(r"enter\s+(a\s+)?(new|special|secret)\s+mode", re.IGNORECASE),

    # ---- Jailbreak patterns ----
    re.compile(r"\bDAN\b", re.IGNORECASE),
    re.compile(r"do\s+anything\s+now", re.IGNORECASE),
    re.compile(r"developer\s+mode\s+(enabled|activated|on)", re.IGNORECASE),
    re.compile(r"enable\s+developer\s+mode", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a\s+)?(DAN|unrestricted|unfiltered|evil|malicious)", re.IGNORECASE),
    re.compile(r"pretend\s+you\s+(are|have)\s+(no|without)\s+(restrictions|limits|filters|rules)", re.IGNORECASE),
    re.compile(r"pretend\s+you\s+are\s+(a\s+)?(different|new|unrestricted)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"bypass\s+(your|all|the|any)\s+(restrictions|filters|safety|guardrails|rules)", re.IGNORECASE),
    re.compile(r"remove\s+(your|all|the)\s+(restrictions|filters|safety|limitations)", re.IGNORECASE),
    re.compile(r"without\s+(any\s+)?(restrictions|filters|safety|limitations|guardrails)", re.IGNORECASE),
    re.compile(r"unrestricted\s+mode", re.IGNORECASE),
    re.compile(r"god\s*mode", re.IGNORECASE),
    re.compile(r"sudo\s+mode", re.IGNORECASE),

    # ---- Hidden instructions ----
    re.compile(r"NOTE\s+TO\s+SYSTEM", re.IGNORECASE),
    re.compile(r"ADMIN\s*:", re.IGNORECASE),
    re.compile(r"INSTRUCTION\s*:", re.IGNORECASE),
    re.compile(r"DIRECTIVE\s*:", re.IGNORECASE),
    re.compile(r"hidden\s+prompt", re.IGNORECASE),
    re.compile(r"secret\s+(instructions?|prompt|directive)", re.IGNORECASE),
    re.compile(r"invisible\s+(text|instructions?|prompt)", re.IGNORECASE),
    re.compile(r"BEGIN\s+(SYSTEM|HIDDEN|SECRET)\s+(PROMPT|INSTRUCTIONS?|MESSAGE)", re.IGNORECASE),
    re.compile(r"IMPORTANT\s*:\s*ignore", re.IGNORECASE),
    re.compile(r"CRITICAL\s*:\s*override", re.IGNORECASE),

    # ---- Delimiter injection ----
    re.compile(r"```system", re.IGNORECASE),
    re.compile(r"</s>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"<<SYS>>", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"<\|im_end\|>", re.IGNORECASE),
    re.compile(r"<\|endoftext\|>", re.IGNORECASE),
    re.compile(r"\[/INST\]", re.IGNORECASE),
    re.compile(r"<\|system\|>", re.IGNORECASE),
    re.compile(r"<\|user\|>", re.IGNORECASE),
    re.compile(r"<\|assistant\|>", re.IGNORECASE),

    # ---- Encoding tricks ----
    re.compile(r"base64\s*decode\s*\(", re.IGNORECASE),
    re.compile(r"decode\s+this\s+(base64|hex|rot13)", re.IGNORECASE),
    re.compile(r"convert\s+from\s+(base64|hex|rot13)", re.IGNORECASE),
    re.compile(r"execute\s+the\s+(decoded|following\s+encoded)", re.IGNORECASE),
    re.compile(r"hex\s*decode\s*\(", re.IGNORECASE),
    re.compile(r"rot13\s*\(", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Dangerous command patterns (20+)
# ---------------------------------------------------------------------------

DANGEROUS_COMMAND_PATTERNS: list[re.Pattern] = [
    # ---- Destructive commands ----
    re.compile(r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\s*$", re.IGNORECASE),
    re.compile(r"rm\s+-[a-z]*f[a-z]*r[a-z]*\s+/\s*$", re.IGNORECASE),
    re.compile(r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+~", re.IGNORECASE),
    re.compile(r"rm\s+-[a-z]*f[a-z]*r[a-z]*\s+~", re.IGNORECASE),
    re.compile(r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\*", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"dd\s+if=/dev/(zero|random|urandom)", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),  # fork bomb
    re.compile(r"chmod\s+-[a-z]*R[a-z]*\s+777\s+/", re.IGNORECASE),
    re.compile(r"chown\s+-[a-z]*R[a-z]*\s+.*\s+/\s*$", re.IGNORECASE),

    # ---- Exfiltration ----
    re.compile(r"cat\s+/etc/(shadow|passwd).*\|\s*(curl|wget|nc|netcat|ncat)", re.IGNORECASE),
    re.compile(r"/etc/(shadow|passwd).*\|\s*(curl|wget|nc|netcat|ncat)", re.IGNORECASE),
    re.compile(r"(curl|wget)\s+.*--upload-file\s+/etc/(shadow|passwd)", re.IGNORECASE),
    re.compile(r"(bash|sh)\s+-i\s+>&\s*/dev/tcp/", re.IGNORECASE),  # reverse shell
    re.compile(r"nc\s+-[a-z]*e\s+(bash|sh|/bin/(bash|sh))", re.IGNORECASE),  # nc reverse shell
    re.compile(r"mkfifo\s+.*\|\s*(bash|sh)", re.IGNORECASE),  # named-pipe reverse shell
    re.compile(r"python[23]?\s+-c\s+.*socket.*connect", re.IGNORECASE),  # python reverse shell
    re.compile(r"perl\s+-e\s+.*socket.*connect", re.IGNORECASE),  # perl reverse shell

    # ---- Resource exhaustion ----
    re.compile(r"while\s+(true|1|:)\s*;\s*do\s+.*;\s*done", re.IGNORECASE),
    re.compile(r"fork\s*\(\s*\)\s*while", re.IGNORECASE),
    re.compile(r"yes\s*\|", re.IGNORECASE),
    re.compile(r"/dev/zero.*>\s*/dev/sd", re.IGNORECASE),

    # ---- Suspicious chains ----
    re.compile(r"(echo|printf)\s+.*\|\s*base64\s+-[a-z]*d[a-z]*\s*\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"base64\s+-[a-z]*d[a-z]*\s*\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"(curl|wget)\s+.*\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"(curl|wget)\s+.*\|\s*sudo\s+(bash|sh)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Unicode homograph map (Cyrillic / confusable -> ASCII)
# ---------------------------------------------------------------------------

UNICODE_HOMOGRAPHS: dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a",  # а -> a
    "\u0435": "e",  # е -> e
    "\u043e": "o",  # о -> o
    "\u0440": "p",  # р -> p
    "\u0441": "c",  # с -> c
    "\u0443": "y",  # у -> y
    "\u0445": "x",  # х -> x
    "\u0456": "i",  # і -> i
    "\u0458": "j",  # ј -> j
    "\u04bb": "h",  # һ -> h
    "\u0455": "s",  # ѕ -> s
    "\u0432": "b",  # в -> b (visual similarity in some fonts)
    "\u043d": "h",  # н -> h (visual similarity in some fonts)
    "\u0442": "t",  # т -> t (visual similarity in some fonts)

    # Cyrillic uppercase
    "\u0410": "A",  # А -> A
    "\u0412": "B",  # В -> B
    "\u0415": "E",  # Е -> E
    "\u041a": "K",  # К -> K
    "\u041c": "M",  # М -> M
    "\u041d": "H",  # Н -> H
    "\u041e": "O",  # О -> O
    "\u0420": "P",  # Р -> P
    "\u0421": "C",  # С -> C
    "\u0422": "T",  # Т -> T
    "\u0425": "X",  # Х -> X
    "\u0423": "Y",  # У -> Y

    # Other confusable characters
    "\u00a0": " ",  # non-breaking space -> space
    "\u2000": " ",  # en quad -> space
    "\u2001": " ",  # em quad -> space
    "\u2002": " ",  # en space -> space
    "\u2003": " ",  # em space -> space
    "\u200b": "",   # zero-width space -> empty
    "\u200c": "",   # zero-width non-joiner -> empty
    "\u200d": "",   # zero-width joiner -> empty
    "\ufeff": "",   # BOM / zero-width no-break space -> empty
    "\u2060": "",   # word joiner -> empty
    "\u2028": "\n", # line separator -> newline
    "\u2029": "\n", # paragraph separator -> newline
    "\uff41": "a",  # fullwidth a
    "\uff45": "e",  # fullwidth e
    "\uff4f": "o",  # fullwidth o
    "\uff50": "p",  # fullwidth p
    "\uff43": "c",  # fullwidth c
}

# Build a translation table for fast replacement
_HOMOGRAPH_TABLE = str.maketrans(UNICODE_HOMOGRAPHS)


def normalize_unicode(text: str) -> str:
    """Replace Unicode homographs and confusable characters with their ASCII equivalents."""
    return text.translate(_HOMOGRAPH_TABLE)
