import logging

from aether.core.logger import configure_logging, get_logger, register_secret


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def _attach_capture():
    # The aether logger does not propagate to root (so caplog can't see it); attach a
    # handler directly. The redactor filter lives on the logger, so records are already
    # redacted by the time any handler sees them.
    configure_logging(level="DEBUG")
    root = logging.getLogger("aether")
    cap = _Capture()
    root.addHandler(cap)
    return cap


def test_registered_flag_is_redacted():
    cap = _attach_capture()
    log = get_logger("redact-test")
    register_secret("CTF{super-secret-flag}")
    log.info("accidentally logging CTF{super-secret-flag} in a message")
    joined = " ".join(cap.messages)
    assert "super-secret-flag" not in joined
    assert "[REDACTED-FLAG]" in joined


def test_non_secret_text_unchanged():
    cap = _attach_capture()
    log = get_logger("redact-test2")
    log.info("normal operational message")
    assert any("normal operational message" in m for m in cap.messages)
