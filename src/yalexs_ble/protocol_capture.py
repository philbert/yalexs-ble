"""One-shot protocol capture for reverse engineering Yale BLE protocol."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Redaction configuration
REDACT_PRESERVE_BYTES = 12  # Increase to 16 or 20 to capture more fields


def redact_bytes(data: bytes, redact: bool) -> str:
    """Redact sensitive bytes while preserving structure for analysis.

    Args:
        data: Raw bytes to redact
        redact: If False, return full hex; if True, preserve first N bytes for structure

    Returns:
        Hex string (pure hex only, possibly truncated)
    """
    if not redact:
        return data.hex()

    if len(data) <= REDACT_PRESERVE_BYTES:
        # Short messages - likely commands/status, safe to show
        return data.hex()

    # Preserve first N bytes for protocol structure analysis
    # Redact remaining bytes (likely secrets/high-entropy data)
    return data[:REDACT_PRESERVE_BYTES].hex()


@dataclass
class CaptureWindow:
    """Tracks capture window state for a single lock."""

    mac: str
    session_id: str
    start_time: float
    end_time: float
    correlation_id: int = 0
    captured: bool = False

    def is_active(self) -> bool:
        """Check if capture window is still active."""
        if self.captured:
            return False
        current = time.monotonic()
        return self.start_time <= current < self.end_time

    def next_correlation_id(self) -> int:
        """Get next correlation ID for this session."""
        self.correlation_id += 1
        return self.correlation_id


class ProtocolCaptureOnceManager:
    """Manages one-shot protocol capture across all locks.

    Captures decrypted protocol frames during the initial connection sequence
    for each lock, then permanently disables capture until integration reload.
    """

    def __init__(
        self,
        enabled: bool,
        capture_path: str,
        redact: bool = True,
        window_duration: float = 15.0,
    ) -> None:
        """Initialize capture manager.

        Args:
            enabled: If False, all capture operations are no-ops
            capture_path: Directory path for capture files
            redact: If True, redact sensitive data in output
            window_duration: How long to capture per lock (seconds)
        """
        self._enabled = enabled
        self._capture_path = Path(capture_path)
        self._redact = redact
        self._window_duration = window_duration

        self._global_enabled = enabled
        self._capture_windows: dict[str, CaptureWindow] = {}
        self._captured_macs: set[str] = set()
        self._file_handle = None
        self._capture_started = False
        self._capture_finished = False
        self._write_lock = threading.Lock()

        if self._enabled:
            self._init_capture_file()
            # Auto-finalize after timeout if no activity
            timer = threading.Timer(300.0, self._auto_finalize)  # 5 minutes
            timer.daemon = True
            timer.start()

    def _init_capture_file(self) -> None:
        """Initialize capture file and write header."""
        if not self._enabled:
            return

        try:
            self._capture_path.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = self._capture_path / f"protocol_capture_{timestamp}.jsonl"

            self._file_handle = open(file_path, "a", encoding="utf-8")

            # Write header event
            import platform
            import sys

            header = {
                "type": "capture_start",
                "ts": datetime.now().isoformat(),
                "python_version": sys.version.split()[0],
                "platform": platform.platform(),
            }

            # Try to get HA version if available
            try:
                from homeassistant import __version__ as ha_version
                header["ha_version"] = ha_version
            except (ImportError, AttributeError):
                pass

            # Try to get integration version
            try:
                from . import __version__
                header["integration_version"] = __version__
            except (ImportError, AttributeError):
                pass

            self._write_event(header)
            self._capture_started = True

            _LOGGER.info("Protocol capture initialized: %s", file_path)
        except Exception as e:
            _LOGGER.error("Failed to initialize protocol capture: %s", e)
            self._enabled = False
            self._global_enabled = False

    def _write_event(self, event: dict[str, Any]) -> None:
        """Write a single event to the capture file."""
        if not self._file_handle:
            return

        try:
            with self._write_lock:
                self._file_handle.write(json.dumps(event) + "\n")
                self._file_handle.flush()
        except Exception as e:
            _LOGGER.error("Failed to write capture event: %s", e)

    def start_capture_window(
        self, mac: str, lock_name: str, session_id: str
    ) -> None:
        """Start capture window for a lock after secure session established.

        Args:
            mac: Lock MAC address
            lock_name: Human-readable lock name
            session_id: Unique session identifier
        """
        if not self._global_enabled:
            return

        if mac in self._captured_macs:
            _LOGGER.debug("Lock %s already captured, skipping", mac)
            return

        current = time.monotonic()
        window = CaptureWindow(
            mac=mac,
            session_id=session_id,
            start_time=current,
            end_time=current + self._window_duration,
        )

        self._capture_windows[mac] = window
        _LOGGER.info(
            "Started capture window for %s (%s), duration: %.1fs",
            lock_name,
            mac,
            self._window_duration,
        )

    def stop_capture_window(self, mac: str) -> None:
        """Stop capture window for a lock (called when initial query completes).

        Args:
            mac: Lock MAC address
        """
        if mac in self._capture_windows:
            window = self._capture_windows[mac]
            window.captured = True
            self._captured_macs.add(mac)
            _LOGGER.info("Stopped capture window for %s", mac)
            self._check_global_done()

    def record_tx(
        self,
        mac: str,
        lock_name: str,
        plaintext: bytes,
        encrypted: bytes | None = None,
        characteristic_uuid: str | None = None,
    ) -> None:
        """Record outbound (TX) protocol frame.

        Args:
            mac: Lock MAC address
            lock_name: Human-readable lock name
            plaintext: Decrypted command bytes
            encrypted: Encrypted command bytes (optional)
            characteristic_uuid: GATT characteristic UUID (optional)
        """
        if not self._global_enabled:
            return

        window = self._capture_windows.get(mac)
        if not window or not window.is_active():
            if window and not window.captured:  # Expired
                window.captured = True
                self._captured_macs.add(mac)
                self._check_global_done()
            return

        event = {
            "ts": datetime.now().isoformat(),
            "lock_name": lock_name,
            "mac": mac,
            "session_id": window.session_id,
            "direction": "tx",
            "transport": "write",
            "characteristic_uuid": characteristic_uuid,
            "plaintext_hex": redact_bytes(plaintext, self._redact),
            "plaintext_len": len(plaintext),
            "correlation_id": window.next_correlation_id(),
        }

        if self._redact and len(plaintext) > REDACT_PRESERVE_BYTES:
            event["plaintext_redacted_bytes"] = len(plaintext) - REDACT_PRESERVE_BYTES

        if encrypted:
            if self._redact:
                event["encrypted_hex"] = f"<REDACTED:{len(encrypted)}bytes>"
            else:
                event["encrypted_hex"] = encrypted.hex()
            event["encrypted_len"] = len(encrypted)

        self._write_event(event)

    def record_rx(
        self,
        mac: str,
        lock_name: str,
        plaintext: bytes,
        encrypted: bytes | None = None,
        characteristic_uuid: str | None = None,
        transport: str = "notify",
    ) -> None:
        """Record inbound (RX) protocol frame.

        Args:
            mac: Lock MAC address
            lock_name: Human-readable lock name
            plaintext: Decrypted response bytes
            encrypted: Encrypted response bytes (optional)
            characteristic_uuid: GATT characteristic UUID (optional)
            transport: Transport type (notify, read, etc.)
        """
        if not self._global_enabled:
            return

        window = self._capture_windows.get(mac)
        if not window or not window.is_active():
            if window and not window.captured:  # Expired
                window.captured = True
                self._captured_macs.add(mac)
                self._check_global_done()
            return

        event = {
            "ts": datetime.now().isoformat(),
            "lock_name": lock_name,
            "mac": mac,
            "session_id": window.session_id,
            "direction": "rx",
            "transport": transport,
            "characteristic_uuid": characteristic_uuid,
            "plaintext_hex": redact_bytes(plaintext, self._redact),
            "plaintext_len": len(plaintext),
            "correlation_id": window.next_correlation_id(),  # Monotonic RX sequence
        }

        if self._redact and len(plaintext) > REDACT_PRESERVE_BYTES:
            event["plaintext_redacted_bytes"] = len(plaintext) - REDACT_PRESERVE_BYTES

        if encrypted:
            if self._redact:
                event["encrypted_hex"] = f"<REDACTED:{len(encrypted)}bytes>"
            else:
                event["encrypted_hex"] = encrypted.hex()
            event["encrypted_len"] = len(encrypted)

        self._write_event(event)

    def _check_global_done(self) -> None:
        """Check if all locks have been captured and finalize."""
        if self._capture_finished:
            return

        # Mark expired windows as captured before checking
        for window in self._capture_windows.values():
            if not window.captured and not window.is_active():
                window.captured = True
                self._captured_macs.add(window.mac)

        # Check if all active windows are done
        all_done = all(
            window.captured or not window.is_active()
            for window in self._capture_windows.values()
        )

        if all_done:
            self._finalize_capture()

    def _auto_finalize(self) -> None:
        """Auto-finalize on timeout - mark expired windows first."""
        for window in self._capture_windows.values():
            if not window.captured and not window.is_active():
                window.captured = True
                self._captured_macs.add(window.mac)
        self._check_global_done()

    def _finalize_capture(self) -> None:
        """Write footer and close capture file."""
        if self._capture_finished:
            return

        self._capture_finished = True
        self._global_enabled = False

        footer = {
            "type": "capture_done",
            "ts": datetime.now().isoformat(),
            "locks_captured": len(self._captured_macs),
            "total_windows": len(self._capture_windows),
        }

        self._write_event(footer)

        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

        _LOGGER.info(
            "Protocol capture finished: %d locks captured",
            len(self._captured_macs),
        )

    def shutdown(self) -> None:
        """Clean shutdown of capture manager."""
        # Mark all expired windows before finalizing
        for window in self._capture_windows.values():
            if not window.captured and not window.is_active():
                window.captured = True
                self._captured_macs.add(window.mac)

        if not self._capture_finished and self._capture_started:
            self._finalize_capture()
        elif self._file_handle:
            self._file_handle.close()
            self._file_handle = None
