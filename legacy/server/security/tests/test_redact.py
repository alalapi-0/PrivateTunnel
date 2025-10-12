import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import redact


def test_key_redaction():
    text = "client_private_key=ABCDEFGHIJKLMNOPQRSTUVWX1234567890+/=="
    result = redact.redact_text(text)
    assert "***KEY_REDACTED***" in result
    assert "ABCDEFGHIJKLMNOP" not in result


def test_domain_redaction():
    text = "endpoint=gw1.internal.example.com"
    result = redact.redact_text(text)
    assert "gw*.********.*******.com" in result


def test_ip_redaction():
    text = "Allowed IP 192.168.99.15"
    result = redact.redact_text(text)
    assert "***.***.99.15" in result
