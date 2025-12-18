"""One-shot protocol capture for reverse engineering Yale BLE protocol."""

from __future__ import annotations

import json
import logging
import threading
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

# Import UUIDs at module level to avoid repeated imports
from .const import (
    SECURE_WRITE_CHARACTERISTIC,
    SECURE_READ_CHARACTERISTIC,
    WRITE_CHARACTERISTIC,
    READ_CHARACTERISTIC,
    Commands,
    StatusType,
    SettingType,
    VALUE_TO_LOCK_STATUS,
    VALUE_TO_DOOR_STATUS,
)

_LOGGER = logging.getLogger(__name__)

# Redaction configuration
REDACT_PRESERVE_BYTES = 18  # Current default; adjust to capture more/fewer fields


def _get_writable_capture_path() -> Path:
    """Determine a writable path for protocol captures.

    Tries paths in order:
    1. /config/yale_captures (Home Assistant OS)
    2. /tmp/yale_captures (fallback)
    3. ~/yale_captures (last resort)

    Returns:
        Path object for first writable directory
    """
    candidates = [
        Path("/config/yale_captures"),
        Path("/tmp/yale_captures"),
        Path.home() / "yale_captures",
    ]

    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            # Test write access
            test_file = path / ".write_test"
            test_file.touch()
            test_file.unlink()
            _LOGGER.info("Protocol capture path selected: %s", path)
            return path
        except (PermissionError, OSError) as e:
            _LOGGER.debug("Path %s not writable: %s", path, e)
            continue

    # Fallback to /tmp if nothing else worked
    fallback = Path("/tmp/yale_captures")
    _LOGGER.warning(
        "No writable capture path found, using fallback: %s", fallback
    )
    return fallback


def _derive_channel(characteristic_uuid: str | None) -> str:
    """Derive channel name from characteristic UUID."""
    if not characteristic_uuid:
        return "unknown"

    uuid_lower = characteristic_uuid.lower()

    if uuid_lower == SECURE_WRITE_CHARACTERISTIC.lower():
        return "secure_write"
    elif uuid_lower == SECURE_READ_CHARACTERISTIC.lower():
        return "secure_read"
    elif uuid_lower == WRITE_CHARACTERISTIC.lower():
        return "plain_write"
    elif uuid_lower == READ_CHARACTERISTIC.lower():
        return "plain_read"
    else:
        return "unknown"


def _derive_fields(plaintext: bytes, characteristic_uuid: str | None) -> dict[str, Any]:
    """Derive decoded fields from plaintext bytes.

    Args:
        plaintext: Decrypted protocol bytes
        characteristic_uuid: GATT characteristic UUID

    Returns:
        Dictionary of derived fields
    """
    fields: dict[str, Any] = {}

    # Channel
    fields["channel"] = _derive_channel(characteristic_uuid)

    if len(plaintext) == 0:
        return fields

    # Frame marker (byte 0)
    frame_marker = plaintext[0]
    fields["frame_marker"] = f"0x{frame_marker:02X}"
    fields["frame_marker_value"] = frame_marker

    if frame_marker == 0xEE:
        fields["frame_marker_name"] = "TX_FRAME"
    elif frame_marker == 0xBB:
        fields["frame_marker_name"] = "RX_FRAME"
    else:
        fields["frame_marker_name"] = "UNKNOWN"

    # Command ID (byte 1)
    if len(plaintext) >= 2:
        command_id = plaintext[1]
        fields["command_id"] = command_id

        # Map to command name
        try:
            command_enum = Commands(command_id)
            fields["command_name"] = command_enum.name
        except ValueError:
            fields["command_name"] = None

    # Type ID (byte 4) - status/setting discriminator
    if len(plaintext) >= 5:
        type_id = plaintext[4]
        fields["type_id"] = type_id

        # Map status type if GETSTATUS (compare int to enum value)
        if fields.get("command_id") == Commands.GETSTATUS.value:
            try:
                status_type = StatusType(type_id)
                fields["status_type_name"] = status_type.name
            except ValueError:
                fields["status_type_name"] = None

        # Map setting type if READSETTING or WRITESETTING (compare int to enum values)
        elif fields.get("command_id") in (Commands.READSETTING.value, Commands.WRITESETTING.value):
            try:
                setting_type = SettingType(type_id)
                fields["setting_type_name"] = setting_type.name
            except ValueError:
                fields["setting_type_name"] = None

    # Payload extraction: header(5) + payload + trailer(2)
    if len(plaintext) >= 7:
        payload = plaintext[5:-2]
        fields["payload_hex"] = payload.hex()
        fields["payload_len"] = len(payload)

        # Scan payload for lock status
        for byte_val in payload:
            if byte_val in VALUE_TO_LOCK_STATUS:
                lock_status = VALUE_TO_LOCK_STATUS[byte_val]
                fields["parsed_lock_status_value"] = byte_val
                fields["parsed_lock_status_name"] = lock_status.name
                break  # First match

        # Scan payload for door status
        for byte_val in payload:
            if byte_val in VALUE_TO_DOOR_STATUS:
                door_status = VALUE_TO_DOOR_STATUS[byte_val]
                fields["parsed_door_status_value"] = byte_val
                fields["parsed_door_status_name"] = door_status.name
                break  # First match
    else:
        fields["payload_hex"] = ""
        fields["payload_len"] = 0

    return fields


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
        capture_path: str | Path | None = None,
        redact: bool = True,
        window_duration: float = 120.0,
    ) -> None:
        """Initialize capture manager.

        Args:
            enabled: If False, all capture operations are no-ops
            capture_path: Directory path for capture files (auto-detected if None)
            redact: If True, redact sensitive data in output
            window_duration: How long to capture per lock (seconds)
        """
        self._enabled = enabled
        self._redact = redact
        self._window_duration = window_duration

        # Auto-detect writable path if not provided
        if capture_path is None:
            self._capture_path = _get_writable_capture_path()
        else:
            self._capture_path = Path(capture_path)

        self._global_enabled = enabled
        self._capture_windows: dict[str, CaptureWindow] = {}
        self._captured_macs: set[str] = set()
        self._file_handle = None
        self._capture_started = False
        self._capture_finished = False
        self._write_lock = threading.Lock()
        self._first_tx_logged = False
        self._first_rx_logged = False

        # Statistics for summary
        self._seen_command_ids: set[int] = set()
        self._seen_type_ids: set[int] = set()
        self._seen_channels: set[str] = set()
        self._seen_plaintext_lengths: set[int] = set()
        self._counts_by_key: dict[tuple, int] = defaultdict(int)

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
            # Ensure directory exists
            self._capture_path.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = self._capture_path / f"protocol_capture_{timestamp}.jsonl"

            # Open file for writing
            self._file_handle = open(file_path, "a", encoding="utf-8")

            # Write header event
            import platform
            import sys

            header = {
                "type": "capture_start",
                "ts": datetime.now().isoformat(),
                "python_version": sys.version.split()[0],
                "platform": platform.platform(),
                "capture_path": str(self._capture_path),
                "window_duration_seconds": self._window_duration,
                "redact_preserve_bytes": REDACT_PRESERVE_BYTES,
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

            _LOGGER.info(
                "Protocol capture initialized successfully: %s (redact=%s, window=%.1fs)",
                file_path,
                self._redact,
                self._window_duration,
            )
        except Exception:
            _LOGGER.error(
                "Failed to initialize protocol capture:\n%s",
                traceback.format_exc(),
            )
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
        except Exception:
            _LOGGER.error(
                "Failed to write capture event:\n%s",
                traceback.format_exc(),
            )

    def _update_statistics(
        self,
        direction: str,
        plaintext_len: int,
        derived: dict[str, Any],
    ) -> None:
        """Update capture statistics for summary."""
        if "command_id" in derived:
            self._seen_command_ids.add(derived["command_id"])
        if "type_id" in derived:
            self._seen_type_ids.add(derived["type_id"])
        if "channel" in derived:
            self._seen_channels.add(derived["channel"])
        self._seen_plaintext_lengths.add(plaintext_len)

        # Count by (direction, command_id, type_id)
        key = (
            direction,
            derived.get("command_id"),
            derived.get("type_id"),
        )
        self._counts_by_key[key] += 1

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

        # Log first TX to prove hooks are working (one-time, cross-lock)
        if not self._first_tx_logged:
            self._first_tx_logged = True
            _LOGGER.info(
                "Protocol capture: First TX recorded (%d bytes)",
                len(plaintext),
            )

        window = self._capture_windows.get(mac)
        if not window or not window.is_active():
            if window and not window.captured:  # Expired
                window.captured = True
                self._captured_macs.add(mac)
                self._check_global_done()
            return

        # Derive fields
        derived = _derive_fields(plaintext, characteristic_uuid)

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
            **derived,  # Add all derived fields
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
        self._update_statistics("tx", len(plaintext), derived)

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

        # Log first RX to prove hooks are working (one-time, cross-lock)
        if not self._first_rx_logged:
            self._first_rx_logged = True
            _LOGGER.info(
                "Protocol capture: First RX recorded (%d bytes)",
                len(plaintext),
            )

        window = self._capture_windows.get(mac)
        if not window or not window.is_active():
            if window and not window.captured:  # Expired
                window.captured = True
                self._captured_macs.add(mac)
                self._check_global_done()
            return

        # Derive fields
        derived = _derive_fields(plaintext, characteristic_uuid)

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
            **derived,  # Add all derived fields
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
        self._update_statistics("rx", len(plaintext), derived)

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

        # Build summary statistics
        footer = {
            "type": "capture_done",
            "ts": datetime.now().isoformat(),
            "locks_captured": len(self._captured_macs),
            "total_windows": len(self._capture_windows),
            "seen_command_ids": sorted(self._seen_command_ids),
            "seen_type_ids": sorted(self._seen_type_ids),
            "seen_channels": sorted(self._seen_channels),
            "seen_plaintext_lengths": sorted(self._seen_plaintext_lengths),
            "counts_by_key": {
                f"{dir}:{cmd}:{typ}": count
                for (dir, cmd, typ), count in self._counts_by_key.items()
            },
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
