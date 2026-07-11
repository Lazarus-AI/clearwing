"""Pure-Python SRP-6a client with 1Password 2SKD support.

Implements RFC 2945 / RFC 5054 Secure Remote Password protocol (version 6a)
with full intermediate value capture for security analysis.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SRPGroupParams:
    """SRP group parameters (safe prime N, generator g)."""

    N: int
    g: int

    @property
    def bits(self) -> int:
        return self.N.bit_length()

    @property
    def N_bytes(self) -> bytes:
        return self.N.to_bytes((self.bits + 7) // 8, "big")

    def pad(self, value: int) -> bytes:
        length = (self.bits + 7) // 8
        return value.to_bytes(length, "big")


# RFC 5054 Appendix A — standard SRP groups.
_N_1024 = int(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
    "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
    "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
    "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
    "FD5138FE8376435B9FC61D2FC0EB06E3",
    16,
)

_N_2048 = int(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294"
    "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D"
    "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB"
    "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74"
    "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A"
    "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D"
    "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73"
    "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F"
    "9E4AFF73",
    16,
)

SRP_GROUPS: dict[int, SRPGroupParams] = {
    1024: SRPGroupParams(N=_N_1024, g=2),
    2048: SRPGroupParams(N=_N_2048, g=2),
}


@dataclass
class SRPHandshakeResult:
    """Complete record of an SRP-6a handshake attempt."""

    success: bool
    username: str
    salt: bytes = b""
    iterations: int = 0
    a: int = 0
    A: int = 0
    B: int = 0
    u: int = 0
    S: int = 0
    K: bytes = b""
    M1: bytes = b""
    M2: bytes | None = None
    group: SRPGroupParams | None = None
    error: str | None = None
    server_responses: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "username": self.username,
            "salt_hex": self.salt.hex(),
            "iterations": self.iterations,
            "a_hex": format(self.a, "x") if self.a else "0",
            "A_hex": format(self.A, "x") if self.A else "0",
            "B_hex": format(self.B, "x") if self.B else "0",
            "u_hex": format(self.u, "x") if self.u else "0",
            "S_hex": format(self.S, "x") if self.S else "0",
            "K_hex": self.K.hex(),
            "M1_hex": self.M1.hex(),
            "M2_hex": self.M2.hex() if self.M2 else None,
            "group_bits": self.group.bits if self.group else None,
            "error": self.error,
            "server_responses": self.server_responses,
        }


class SRPClient:
    """SRP-6a client — stateless methods for security analysis."""

    def __init__(self, group: SRPGroupParams, hash_func: str = "sha256") -> None:
        self.group = group
        self.hash_func = hash_func

    def _hash(self, *args: bytes) -> bytes:
        h = hashlib.new(self.hash_func)
        for a in args:
            h.update(a)
        return h.digest()

    def _hash_int(self, *args: bytes) -> int:
        return int.from_bytes(self._hash(*args), "big")

    def compute_k(self) -> int:
        """k = H(N | pad(g)) — SRP-6a multiplier."""
        return self._hash_int(self.group.N_bytes, self.group.pad(self.group.g))

    def generate_a(self) -> tuple[int, int]:
        """Generate private a and public A = g^a mod N."""
        N = self.group.N
        a = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
        A = pow(self.group.g, a, N)
        return a, A

    def compute_u(self, A: int, B: int) -> int:
        """u = H(pad(A) | pad(B))."""
        return self._hash_int(self.group.pad(A), self.group.pad(B))

    def compute_x(self, salt: bytes, identity: str, password: str) -> int:
        """x = H(salt | H(identity | ':' | password))."""
        inner = self._hash(f"{identity}:{password}".encode())
        return self._hash_int(salt, inner)

    def compute_S(self, B: int, a: int, u: int, x: int) -> int:
        """S = (B - k*g^x)^(a + u*x) mod N."""
        N = self.group.N
        k = self.compute_k()
        g_x = pow(self.group.g, x, N)
        base = (B - k * g_x) % N
        exp = (a + u * x) % (N - 1)
        return pow(base, exp, N)

    def compute_K(self, S: int) -> bytes:
        """K = H(S) — session key."""
        length = (self.group.bits + 7) // 8
        return self._hash(S.to_bytes(length, "big"))

    def compute_M1(
        self,
        identity: str,
        salt: bytes,
        A: int,
        B: int,
        K: bytes,
    ) -> bytes:
        """M1 = H(H(N) XOR H(g) | H(I) | salt | pad(A) | pad(B) | K)."""
        H_N = self._hash(self.group.N_bytes)
        H_g = self._hash(self.group.pad(self.group.g))
        xor_ng = bytes(a ^ b for a, b in zip(H_N, H_g, strict=True))
        H_I = self._hash(identity.encode())
        return self._hash(
            xor_ng,
            H_I,
            salt,
            self.group.pad(A),
            self.group.pad(B),
            K,
        )

    def compute_M2(self, A: int, M1: bytes, K: bytes) -> bytes:
        """M2 = H(pad(A) | M1 | K) — server proof."""
        return self._hash(self.group.pad(A), M1, K)

    def verify_M2(self, A: int, M1: bytes, K: bytes, M2: bytes) -> bool:
        """Verify server proof."""
        expected = self.compute_M2(A, M1, K)
        return hmac.compare_digest(expected, M2)

    def full_handshake(
        self,
        identity: str,
        password: str,
        salt: bytes,
        B: int,
    ) -> SRPHandshakeResult:
        """Execute complete client-side SRP computation."""
        a, A = self.generate_a()
        u = self.compute_u(A, B)
        if u == 0:
            return SRPHandshakeResult(
                success=False,
                username=identity,
                salt=salt,
                a=a,
                A=A,
                B=B,
                u=0,
                group=self.group,
                error="u == 0, aborting (server may be malicious)",
            )
        x = self.compute_x(salt, identity, password)
        S = self.compute_S(B, a, u, x)
        K = self.compute_K(S)
        M1 = self.compute_M1(identity, salt, A, B, K)
        return SRPHandshakeResult(
            success=True,
            username=identity,
            salt=salt,
            a=a,
            A=A,
            B=B,
            u=u,
            S=S,
            K=K,
            M1=M1,
            group=self.group,
        )


def parse_secret_key(secret_key: str) -> bytes:
    """Parse 1Password Secret Key from A3-XXXXXX-... format to raw bytes."""
    cleaned = secret_key.replace("-", "")
    if cleaned.startswith("A3"):
        cleaned = cleaned[2:]
    return bytes.fromhex(cleaned) if all(c in "0123456789abcdefABCDEF" for c in cleaned) else cleaned.encode()


def derive_2skd(
    password: str,
    salt: bytes,
    iterations: int,
    secret_key: bytes,
    hash_func: str = "sha256",
    dk_len: int = 64,
) -> tuple[bytes, int]:
    """1Password 2SKD: PBKDF2(password, salt, iterations) XOR secret_key.

    Returns (auk_bytes, srp_x_int) where the derived key is split in half.
    """
    dk = hashlib.pbkdf2_hmac(hash_func, password.encode(), salt, iterations, dklen=dk_len)
    padded_key = secret_key.ljust(dk_len, b"\x00")[:dk_len]
    xored = bytes(a ^ b for a, b in zip(dk, padded_key, strict=True))
    half = dk_len // 2
    auk = xored[:half]
    srp_x = int.from_bytes(xored[half:], "big")
    return auk, srp_x
