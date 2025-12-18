"""Tests for protocol capture functionality."""

import json
import tempfile
import time
from pathlib import Path

import pytest

from yalexs_ble.protocol_capture import (
    ProtocolCaptureOnceManager,
    redact_bytes,
)


def test_redact_bytes_disabled():
    """Test redaction when disabled."""
    data = b"\xee\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    result = redact_bytes(data, redact=False)
    assert result == data.hex()


def test_redact_bytes_enabled():
    """Test redaction when enabled."""
    data = b"\xee\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    result = redact_bytes(data, redact=True)
    # Should preserve first 12 bytes (24 hex chars) and truncate the rest
    assert result == "ee0102030405060708090a0b"
    assert len(result) == 24  # 12 bytes = 24 hex chars


def test_redact_bytes_short():
    """Test redaction with short data."""
    data = b"\xee\x01\x02"
    result = redact_bytes(data, redact=True)
    # Too short to redact, returns full hex
    assert result == data.hex()


def test_capture_disabled():
    """Test that disabled capture does nothing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = ProtocolCaptureOnceManager(
            enabled=False,
            capture_path=tmpdir,
            redact=True,
        )

        # Should be no-ops
        manager.start_capture_window("AA:BB:CC:DD:EE:FF", "Test Lock", "session1")
        manager.record_tx(
            "AA:BB:CC:DD:EE:FF",
            "Test Lock",
            b"\xee\x01\x02\x03",
        )
        manager.record_rx(
            "AA:BB:CC:DD:EE:FF",
            "Test Lock",
            b"\xbb\x02\x03\x04",
        )

        # No files should be created
        assert not list(Path(tmpdir).glob("*.jsonl"))


def test_capture_one_shot():
    """Test one-shot capture logic."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = ProtocolCaptureOnceManager(
            enabled=True,
            capture_path=tmpdir,
            redact=False,
            window_duration=1.0,
        )

        mac = "AA:BB:CC:DD:EE:FF"
        lock_name = "Test Lock"
        session_id = "session1"

        # Start capture window
        manager.start_capture_window(mac, lock_name, session_id)

        # Record some events
        manager.record_tx(mac, lock_name, b"\xee\x01\x02\x03")
        manager.record_rx(mac, lock_name, b"\xbb\x02\x03\x04")

        # Stop capture window
        manager.stop_capture_window(mac)

        # Try to record more - should be no-op
        manager.record_tx(mac, lock_name, b"\xee\x05\x06\x07")

        # Shutdown to flush
        manager.shutdown()

        # Check file was created
        files = list(Path(tmpdir).glob("protocol_capture_*.jsonl"))
        assert len(files) == 1

        # Read and verify contents
        with open(files[0]) as f:
            lines = f.readlines()

        events = [json.loads(line) for line in lines]

        # Should have: header, tx, rx, footer
        assert len(events) == 4
        assert events[0]["type"] == "capture_start"
        assert events[1]["direction"] == "tx"
        assert events[1]["plaintext_hex"] == "ee010203"
        assert events[2]["direction"] == "rx"
        assert events[2]["plaintext_hex"] == "bb020304"
        assert events[3]["type"] == "capture_done"
        assert events[3]["locks_captured"] == 1


def test_capture_window_timeout():
    """Test that capture window times out."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = ProtocolCaptureOnceManager(
            enabled=True,
            capture_path=tmpdir,
            redact=False,
            window_duration=0.1,  # 100ms
        )

        mac = "AA:BB:CC:DD:EE:FF"
        lock_name = "Test Lock"
        session_id = "session1"

        # Start capture window
        manager.start_capture_window(mac, lock_name, session_id)

        # Record during window
        manager.record_tx(mac, lock_name, b"\xee\x01\x02\x03")

        # Wait for timeout
        time.sleep(0.2)

        # Record after timeout - should be no-op
        manager.record_tx(mac, lock_name, b"\xee\x05\x06\x07")

        manager.shutdown()

        # Check file
        files = list(Path(tmpdir).glob("protocol_capture_*.jsonl"))
        assert len(files) == 1

        with open(files[0]) as f:
            events = [json.loads(line) for line in f.readlines()]

        # Should only have first TX, not second
        tx_events = [e for e in events if e.get("direction") == "tx"]
        assert len(tx_events) == 1
        assert tx_events[0]["plaintext_hex"] == "ee010203"


def test_no_duplicate_capture():
    """Test that a lock is only captured once."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = ProtocolCaptureOnceManager(
            enabled=True,
            capture_path=tmpdir,
            redact=False,
        )

        mac = "AA:BB:CC:DD:EE:FF"
        lock_name = "Test Lock"

        # First capture
        manager.start_capture_window(mac, lock_name, "session1")
        manager.record_tx(mac, lock_name, b"\xee\x01")
        manager.stop_capture_window(mac)

        # Try second capture - should be no-op
        manager.start_capture_window(mac, lock_name, "session2")
        manager.record_tx(mac, lock_name, b"\xee\x02")

        manager.shutdown()

        # Check file
        files = list(Path(tmpdir).glob("protocol_capture_*.jsonl"))
        assert len(files) == 1

        with open(files[0]) as f:
            events = [json.loads(line) for line in f.readlines()]

        # Should only have first TX
        tx_events = [e for e in events if e.get("direction") == "tx"]
        assert len(tx_events) == 1
        assert tx_events[0]["plaintext_hex"] == "ee01"


def test_redaction_enabled():
    """Test that redaction works in capture."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = ProtocolCaptureOnceManager(
            enabled=True,
            capture_path=tmpdir,
            redact=True,  # Enable redaction
        )

        mac = "AA:BB:CC:DD:EE:FF"
        lock_name = "Test Lock"
        session_id = "session1"

        manager.start_capture_window(mac, lock_name, session_id)

        # Record with encryption data
        plaintext = b"\xee\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        encrypted = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"

        manager.record_tx(mac, lock_name, plaintext, encrypted)

        manager.shutdown()

        # Check file
        files = list(Path(tmpdir).glob("protocol_capture_*.jsonl"))
        assert len(files) == 1

        with open(files[0]) as f:
            events = [json.loads(line) for line in f.readlines()]

        tx_events = [e for e in events if e.get("direction") == "tx"]
        assert len(tx_events) == 1

        # Check redaction - plaintext_hex should be pure hex (first 12 bytes)
        assert tx_events[0]["plaintext_hex"] == "ee0102030405060708090a0b"
        assert tx_events[0]["plaintext_redacted_bytes"] == 4  # 16 - 12 = 4 bytes redacted
        assert tx_events[0]["encrypted_hex"] == "<REDACTED:16bytes>"
        assert tx_events[0]["plaintext_len"] == 16
        assert tx_events[0]["encrypted_len"] == 16


def test_correlation_id():
    """Test that correlation IDs are sequential per session."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = ProtocolCaptureOnceManager(
            enabled=True,
            capture_path=tmpdir,
            redact=False,
        )

        mac = "AA:BB:CC:DD:EE:FF"
        lock_name = "Test Lock"
        session_id = "session1"

        manager.start_capture_window(mac, lock_name, session_id)

        # Record TX/RX pairs
        manager.record_tx(mac, lock_name, b"\xee\x01")
        manager.record_rx(mac, lock_name, b"\xbb\x01")
        manager.record_tx(mac, lock_name, b"\xee\x02")
        manager.record_rx(mac, lock_name, b"\xbb\x02")

        manager.shutdown()

        # Check file
        files = list(Path(tmpdir).glob("protocol_capture_*.jsonl"))
        with open(files[0]) as f:
            events = [json.loads(line) for line in f.readlines()]

        comm_events = [e for e in events if e.get("direction")]

        # Check correlation IDs are monotonic (each event gets unique ID)
        assert comm_events[0]["correlation_id"] == 1  # First TX
        assert comm_events[1]["correlation_id"] == 2  # First RX (monotonic)
        assert comm_events[2]["correlation_id"] == 3  # Second TX
        assert comm_events[3]["correlation_id"] == 4  # Second RX (monotonic)
