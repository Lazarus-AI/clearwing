import io
from contextlib import redirect_stdout

import pytest

from clearwing.exploitation.payloads.authorization import AuthorizationGate
from clearwing.exploitation.payloads.obfuscator import PayloadObfuscator
from clearwing.exploitation.payloads.watermark import Watermarker


def test_payload_obfuscation_requires_authorization():
    """Test that obfuscation is gated behind authorization."""
    AuthorizationGate.revoke()
    with pytest.raises(PermissionError):
        PayloadObfuscator.generate_polymorphic_python("print('test')")


def test_payload_obfuscation():
    """Test that polymorphic Python payloads execute correctly."""
    AuthorizationGate.authorize("payload_obfuscation")
    original_payload = "print('HELLOWORLD')"
    obfuscated = PayloadObfuscator.generate_polymorphic_python(original_payload)
    AuthorizationGate.revoke()

    assert "import base64" in obfuscated
    assert "exec(" in obfuscated

    # Capture output of the obfuscated payload
    f = io.StringIO()
    with redirect_stdout(f):
        exec(obfuscated)

    assert f.getvalue().strip() == "HELLOWORLD"


def test_payload_watermarking():
    """Test that payloads can be signed and verified."""
    payload = "rm -rf /"
    marker = Watermarker(shared_secret="TEST-SECRET")

    signed = marker.sign_payload(payload, "OP-TEST")
    assert signed.startswith("### WATERMARK")
    assert "OPID:OP-TEST" in signed
    assert "SIG:" in signed

    # Verify valid payload
    assert marker.verify_payload(signed)

    # Verify modified (malicious) payload fails
    malicious = signed.replace("rm -rf /", "rm -rf / --no-preserve-root")
    assert not marker.verify_payload(malicious)

    # Verify payload with wrong secret fails
    marker2 = Watermarker(shared_secret="WRONG-SECRET")
    assert not marker2.verify_payload(signed)
