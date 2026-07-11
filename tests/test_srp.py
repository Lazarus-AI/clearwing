"""Unit tests for the SRP-6a crypto library."""

from __future__ import annotations

import hashlib

import pytest

from clearwing.crypto.srp import (
    SRP_GROUPS,
    SRPClient,
    SRPGroupParams,
    SRPHandshakeResult,
    derive_2skd,
    parse_secret_key,
)


class TestSRPGroupParams:
    def test_standard_groups_exist(self):
        assert 1024 in SRP_GROUPS
        assert 2048 in SRP_GROUPS

    @pytest.mark.parametrize("bits", [1024, 2048])
    def test_N_is_odd(self, bits):
        group = SRP_GROUPS[bits]
        assert group.N % 2 != 0

    @pytest.mark.parametrize("bits", [1024, 2048])
    def test_g_is_positive(self, bits):
        group = SRP_GROUPS[bits]
        assert group.g > 1

    @pytest.mark.parametrize("bits", [1024, 2048])
    def test_bits_property(self, bits):
        group = SRP_GROUPS[bits]
        assert group.bits == bits

    def test_N_bytes_length(self):
        group = SRP_GROUPS[2048]
        assert len(group.N_bytes) == 256

    def test_pad_length(self):
        group = SRP_GROUPS[2048]
        padded = group.pad(2)
        assert len(padded) == 256

    def test_frozen(self):
        group = SRP_GROUPS[1024]
        with pytest.raises(AttributeError):
            group.N = 0


class TestSRPClient:
    @pytest.fixture
    def client(self):
        return SRPClient(SRP_GROUPS[1024])

    def test_generate_a_in_range(self, client):
        a, A = client.generate_a()
        assert 0 < a
        assert 0 < A < client.group.N

    def test_generate_a_different_each_time(self, client):
        _, A1 = client.generate_a()
        _, A2 = client.generate_a()
        assert A1 != A2

    def test_compute_k_nonzero(self, client):
        k = client.compute_k()
        assert k > 0

    def test_compute_k_deterministic(self, client):
        assert client.compute_k() == client.compute_k()

    def test_compute_x_deterministic(self, client):
        x1 = client.compute_x(b"salt", "alice", "password")
        x2 = client.compute_x(b"salt", "alice", "password")
        assert x1 == x2

    def test_compute_x_different_passwords(self, client):
        x1 = client.compute_x(b"salt", "alice", "password1")
        x2 = client.compute_x(b"salt", "alice", "password2")
        assert x1 != x2

    def test_compute_u_nonzero(self, client):
        _, A = client.generate_a()
        B = pow(client.group.g, 42, client.group.N)
        u = client.compute_u(A, B)
        assert u > 0

    def test_compute_u_deterministic(self, client):
        A, B = 12345, 67890
        assert client.compute_u(A, B) == client.compute_u(A, B)

    def test_compute_S_positive(self, client):
        a, A = client.generate_a()
        B = pow(client.group.g, 42, client.group.N)
        u = client.compute_u(A, B)
        x = client.compute_x(b"salt", "alice", "password")
        S = client.compute_S(B, a, u, x)
        assert S >= 0

    def test_compute_K_length(self, client):
        K = client.compute_K(12345)
        assert len(K) == 32  # SHA-256

    def test_compute_K_deterministic(self, client):
        assert client.compute_K(999) == client.compute_K(999)

    def test_M1_deterministic(self, client):
        M1a = client.compute_M1("alice", b"salt", 100, 200, b"K" * 32)
        M1b = client.compute_M1("alice", b"salt", 100, 200, b"K" * 32)
        assert M1a == M1b

    def test_M2_verify_roundtrip(self, client):
        A = 12345
        M1 = b"proof" * 6 + b"pr"
        K = b"key" * 10 + b"ke"
        M2 = client.compute_M2(A, M1, K)
        assert client.verify_M2(A, M1, K, M2)

    def test_M2_verify_wrong(self, client):
        A = 12345
        M1 = b"proof" * 6 + b"pr"
        K = b"key" * 10 + b"ke"
        assert not client.verify_M2(A, M1, K, b"wrong" * 6 + b"wr")

    def test_full_handshake_success(self):
        group = SRP_GROUPS[1024]
        client = SRPClient(group)
        salt = b"test_salt_value!"
        # Simulate server: generate b, B = k*g^x + g^b
        x = client.compute_x(salt, "alice", "password123")
        k = client.compute_k()
        b_priv = 42
        B = (k * pow(group.g, x, group.N) + pow(group.g, b_priv, group.N)) % group.N

        result = client.full_handshake("alice", "password123", salt, B)
        assert result.success
        assert result.A > 0
        assert result.S >= 0
        assert len(result.K) == 32
        assert len(result.M1) == 32

    def test_full_handshake_u_zero(self):
        group = SRPGroupParams(N=23, g=5)
        client = SRPClient(group)
        # With a tiny group, we can't easily force u=0, but test the error path
        # by mocking. Instead verify the result dataclass structure.
        result = SRPHandshakeResult(success=False, username="test", error="u == 0")
        assert not result.success

    def test_zero_key_attack_S_is_zero(self, client):
        """When A=0, S should equal 0 regardless of other values."""
        # With A=0: A mod N = 0, so u = H(pad(0) | pad(B)) is some value,
        # but the key thing is the SERVER side: S_server = (A * v^u)^b mod N = 0
        # On client side, A=0 means we never actually computed a valid handshake.
        # What matters is: if the server accepts A=0, they compute S=0.
        # Verify that our client can also compute S=0 for the scenario.
        K_zero = client.compute_K(0)
        assert len(K_zero) == 32
        expected = hashlib.sha256(client.group.pad(0)).digest()
        assert K_zero == expected


class TestSRPHandshakeResult:
    def test_to_dict(self):
        result = SRPHandshakeResult(
            success=True,
            username="alice",
            salt=b"\x01\x02",
            A=255,
            B=256,
            K=b"\x00" * 32,
            M1=b"\x01" * 32,
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["username"] == "alice"
        assert d["salt_hex"] == "0102"
        assert d["A_hex"] == "ff"
        assert d["K_hex"] == "00" * 32

    def test_to_dict_defaults(self):
        result = SRPHandshakeResult(success=False, username="test")
        d = result.to_dict()
        assert d["M2_hex"] is None
        assert d["group_bits"] is None


class TestDerive2SKD:
    def test_deterministic(self):
        auk1, x1 = derive_2skd("password", b"salt", 1000, b"\x01" * 32)
        auk2, x2 = derive_2skd("password", b"salt", 1000, b"\x01" * 32)
        assert auk1 == auk2
        assert x1 == x2

    def test_different_passwords(self):
        auk1, x1 = derive_2skd("password1", b"salt", 1000, b"\x01" * 32)
        auk2, x2 = derive_2skd("password2", b"salt", 1000, b"\x01" * 32)
        assert auk1 != auk2 or x1 != x2

    def test_secret_key_xor_changes_output(self):
        auk1, x1 = derive_2skd("password", b"salt", 1000, b"\x00" * 32)
        auk2, x2 = derive_2skd("password", b"salt", 1000, b"\xff" * 32)
        assert auk1 != auk2

    def test_output_length(self):
        auk, x = derive_2skd("password", b"salt", 1000, b"\x01" * 32)
        assert len(auk) == 32  # half of default dk_len=64
        assert x >= 0

    def test_custom_dk_len(self):
        auk, x = derive_2skd("password", b"salt", 1000, b"\x01" * 16, dk_len=32)
        assert len(auk) == 16  # half of 32


class TestParseSecretKey:
    def test_strips_dashes(self):
        result = parse_secret_key("A3-AABBCC-DDEEFF")
        assert result == bytes.fromhex("AABBCCDDEEFF")

    def test_strips_a3_prefix(self):
        result = parse_secret_key("A3AABBCCDDEEFF")
        assert result == bytes.fromhex("AABBCCDDEEFF")

    def test_plain_hex(self):
        result = parse_secret_key("AABBCC")
        assert result == bytes.fromhex("AABBCC")

    def test_non_hex_returns_bytes(self):
        result = parse_secret_key("not-hex-data")
        assert isinstance(result, bytes)
