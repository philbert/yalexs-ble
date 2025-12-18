"""One-shot GETSTATUS type_id fuzzing to discover battery-related responses.

This module implements safe, sequential fuzzing of the type_id byte in GETSTATUS
commands to discover undocumented battery status responses on Yale locks.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .const import Commands, StatusType
from .session import DisconnectedError

_LOGGER = logging.getLogger(__name__)

# Fuzzing configuration
FUZZ_START = 0x00
FUZZ_END = 0x3F
RESPONSE_TIMEOUT = 0.6  # 600ms
REQUEST_DELAY = 0.1  # 100ms between requests
MAX_CONCURRENT_LOCKS = 2  # Global concurrency limit
PAYLOAD_PREVIEW_BYTES = 8  # Capture first N bytes of payload
GLOBAL_FINALIZE_TIMEOUT = 600  # 10 minutes global timeout for finalization

# Known valid status types to skip
KNOWN_STATUS_TYPES = {
    StatusType.LOCK_ONLY.value,
    StatusType.DOOR_ONLY.value,
    StatusType.DOOR_AND_LOCK.value,
    StatusType.BATTERY.value,
}


@dataclass
class FuzzResult:
    """Result of fuzzing a single type_id value."""

    type_id: int
    result: str  # "response" or "timeout"
    plaintext_len: int | None = None
    payload_len: int | None = None
    payload_preview: str | None = None  # Hex string


@dataclass
class LockFuzzResults:
    """Fuzzing results for a single lock."""

    lock_name: str
    mac: str
    attempted: int = 0
    responses: list[int] = field(default_factory=list)
    timeouts: list[int] = field(default_factory=list)
    skipped: list[int] = field(default_factory=list)
    control_samples: dict[str, dict[str, Any]] = field(default_factory=dict)
    candidates: dict[str, dict[str, Any]] = field(default_factory=dict)


class BatteryFuzzManager:
    """Manages one-shot battery fuzzing across all locks.

    This runs once per integration lifetime after locks connect and complete
    initial status queries.
    """

    def __init__(
        self,
        enabled: bool = True,
        capture_path: str | Path | None = None,
    ) -> None:
        """Initialize fuzzing manager.

        Args:
            enabled: If False, fuzzing is disabled
            capture_path: Directory for output files (auto-detected if None)
        """
        self._enabled = enabled
        self._capture_path = Path(capture_path) if capture_path else Path("/config/yale_captures")
        self._fuzzed_macs: set[str] = set()
        self._results: dict[str, LockFuzzResults] = {}
        self._global_semaphore = asyncio.Semaphore(MAX_CONCURRENT_LOCKS)
        self._started = False
        self._finished = False
        self._active_tasks: set[str] = set()  # Track active fuzzing tasks by MAC
        self._finalize_timer_task: asyncio.Task | None = None

    def should_fuzz(self, mac: str) -> bool:
        """Check if a lock should be fuzzed.

        Args:
            mac: Lock MAC address

        Returns:
            True if lock hasn't been fuzzed yet
        """
        if not self._enabled:
            return False
        return mac not in self._fuzzed_macs

    async def fuzz_lock(
        self,
        mac: str,
        lock_name: str,
        send_command_func,
        disconnect_event: asyncio.Event | None = None,
        build_command_func=None,
    ) -> None:
        """Fuzz GETSTATUS type_id values for a single lock.

        Args:
            mac: Lock MAC address
            lock_name: Human-readable lock name
            send_command_func: Async function to send commands (from session.execute)
            disconnect_event: Event set when lock disconnects (optional)
            build_command_func: Function to build GETSTATUS command (opcode, type_id) -> bytearray (required)
        """
        if not self._enabled:
            return

        if mac in self._fuzzed_macs:
            _LOGGER.debug("Lock %s already fuzzed, skipping", mac)
            return

        if build_command_func is None:
            _LOGGER.error("Lock %s: build_command_func is required for fuzzing", mac)
            return

        # Mark as fuzzed immediately to prevent duplicate runs
        self._fuzzed_macs.add(mac)

        if not self._started:
            self._started = True
            _LOGGER.info(
                "Battery fuzzing started: type_id range 0x%02X-0x%02X, timeout=%.1fms",
                FUZZ_START,
                FUZZ_END,
                RESPONSE_TIMEOUT * 1000,
            )
            # Start global finalize timer on first lock
            self._start_finalize_timer()

        # Add to active tasks
        self._active_tasks.add(mac)

        # One-time validation: verify that byte 0x04 in built command equals type_id
        try:
            test_type_id = StatusType.BATTERY.value
            test_command = build_command_func(Commands.GETSTATUS.value, test_type_id)
            if test_command[0x04] != test_type_id:
                _LOGGER.error(
                    "Lock %s: Command builder validation failed: byte 0x04 (0x%02X) != type_id (0x%02X). Aborting fuzzing.",
                    mac,
                    test_command[0x04],
                    test_type_id,
                )
                self._active_tasks.discard(mac)
                return
            _LOGGER.debug(
                "Lock %s: Command builder validated: byte 0x04 matches type_id",
                mac,
            )
        except Exception as e:
            _LOGGER.error(
                "Lock %s: Command builder validation error: %s. Aborting fuzzing.",
                mac,
                e,
            )
            self._active_tasks.discard(mac)
            return

        # Acquire global semaphore to limit concurrent fuzzing
        async with self._global_semaphore:
            _LOGGER.info(
                "Battery fuzzing lock: %s (%s), range 0x%02X-0x%02X",
                lock_name,
                mac,
                FUZZ_START,
                FUZZ_END,
            )

            results = LockFuzzResults(lock_name=lock_name, mac=mac)
            self._results[mac] = results

            # Track attempts for debug logging
            attempt_count = 0

            # Fuzz each type_id sequentially
            for type_id in range(FUZZ_START, FUZZ_END + 1):
                # Check if disconnected
                if disconnect_event and disconnect_event.is_set():
                    _LOGGER.warning(
                        "Lock %s disconnected during fuzzing at type_id 0x%02X",
                        mac,
                        type_id,
                    )
                    break

                # Determine if this is a control sample (known type)
                is_control = type_id in KNOWN_STATUS_TYPES

                # Skip known non-BATTERY types (already tested by integration)
                if is_control and type_id != StatusType.BATTERY.value:
                    results.skipped.append(type_id)
                    continue

                results.attempted += 1

                try:
                    # Build fresh GETSTATUS command with type_id
                    # This ensures fresh sequence/nonce for each request
                    command = build_command_func(Commands.GETSTATUS.value, type_id)

                    # Debug: Log first 3 commands to verify freshness (plaintext only, pre-encryption)
                    if attempt_count < 3:
                        _LOGGER.debug(
                            "Lock %s fuzz attempt %d: type_id=0x%02X, plaintext[0:5]=%s",
                            mac,
                            attempt_count + 1,
                            type_id,
                            command[0:5].hex(),
                        )

                    # Send command and wait for response
                    start = time.monotonic()
                    try:
                        # Use existing send path with timeout
                        response = await asyncio.wait_for(
                            send_command_func(command),
                            timeout=RESPONSE_TIMEOUT,
                        )

                        # Got a response
                        elapsed = time.monotonic() - start
                        results.responses.append(type_id)

                        # Extract payload for analysis
                        plaintext_len = len(response) if response else 0
                        payload_len = 0
                        payload_preview = None

                        if response and len(response) >= 7:
                            payload = response[5:-2]  # header(5) + payload + trailer(2)
                            payload_len = len(payload)
                            preview_len = min(payload_len, PAYLOAD_PREVIEW_BYTES)
                            payload_preview = payload[:preview_len].hex()

                        # Build result record
                        result_record = {
                            "type_id": type_id,
                            "plaintext_len": plaintext_len,
                            "payload_len": payload_len,
                            "payload_preview": payload_preview,
                            "response_time_ms": int(elapsed * 1000),
                        }

                        # Record as control sample or candidate
                        if is_control:
                            results.control_samples[f"0x{type_id:02X}"] = result_record
                            _LOGGER.debug(
                                "Fuzz lock %s type_id 0x%02X (control): response (%d bytes, payload=%d)",
                                mac,
                                type_id,
                                plaintext_len,
                                payload_len,
                            )
                        else:
                            results.candidates[f"0x{type_id:02X}"] = result_record
                            _LOGGER.debug(
                                "Fuzz lock %s type_id 0x%02X: response (%d bytes, payload=%d)",
                                mac,
                                type_id,
                                plaintext_len,
                                payload_len,
                            )

                    except asyncio.TimeoutError:
                        # Timeout - no response
                        results.timeouts.append(type_id)
                        if is_control:
                            _LOGGER.warning(
                                "Fuzz lock %s type_id 0x%02X (control): timeout",
                                mac,
                                type_id,
                            )
                        else:
                            _LOGGER.debug("Fuzz lock %s type_id 0x%02X: timeout", mac, type_id)

                    # Small delay between requests
                    await asyncio.sleep(REQUEST_DELAY)

                    # Increment attempt counter
                    attempt_count += 1

                except DisconnectedError as e:
                    # Disconnected during fuzzing - abort immediately
                    _LOGGER.warning(
                        "Lock %s disconnected during fuzz attempt at type_id 0x%02X: %s",
                        mac,
                        type_id,
                        e,
                    )
                    break

                except Exception as e:
                    _LOGGER.error(
                        "Fuzz lock %s type_id 0x%02X failed: %s",
                        mac,
                        type_id,
                        e,
                    )
                    results.timeouts.append(type_id)

            _LOGGER.info(
                "Battery fuzzing complete for %s: %d attempted, %d responses, %d timeouts",
                lock_name,
                results.attempted,
                len(results.responses),
                len(results.timeouts),
            )

        # Remove from active tasks
        self._active_tasks.discard(mac)

        # Check if all locks done, then finalize
        await self._check_finalize()

    def _start_finalize_timer(self) -> None:
        """Start global finalize timer (backstop)."""
        async def _timer():
            try:
                await asyncio.sleep(GLOBAL_FINALIZE_TIMEOUT)
                if not self._finished:
                    _LOGGER.info(
                        "Battery fuzzing global timeout (%ds) elapsed, finalizing",
                        GLOBAL_FINALIZE_TIMEOUT,
                    )
                    await self._finalize()
            except asyncio.CancelledError:
                pass

        self._finalize_timer_task = asyncio.create_task(_timer())

    async def _check_finalize(self) -> None:
        """Check if all fuzzing is complete and write summary."""
        # This is called after each lock completes, but we only finalize once
        if self._finished:
            return

        # Finalize only when all active tasks are complete
        if not self._active_tasks and self._results:
            _LOGGER.info("All battery fuzzing tasks complete, finalizing")
            # Cancel finalize timer since we're done
            if self._finalize_timer_task:
                self._finalize_timer_task.cancel()
            await self._finalize()

    async def _finalize(self) -> None:
        """Write fuzzing summary to disk."""
        if self._finished:
            return

        self._finished = True

        try:
            # Ensure directory exists
            self._capture_path.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            summary_path = self._capture_path / f"battery_fuzz_summary_{timestamp}.json"

            # Build cross-lock analysis
            type_id_counts: dict[int, int] = {}
            for lock_results in self._results.values():
                for type_id in lock_results.responses:
                    type_id_counts[type_id] = type_id_counts.get(type_id, 0) + 1

            # Cross-lock candidates: responded on ≥2 locks
            cross_lock_candidates = sorted(
                [f"0x{tid:02X}" for tid, count in type_id_counts.items() if count >= 2]
            )

            # Build summary
            summary = {
                "run_ts": datetime.now().isoformat(),
                "range": f"0x{FUZZ_START:02X}-0x{FUZZ_END:02X}",
                "known_types_skipped": [f"0x{tid:02X}" for tid in sorted(KNOWN_STATUS_TYPES)],
                "timeout_ms": int(RESPONSE_TIMEOUT * 1000),
                "delay_ms": int(REQUEST_DELAY * 1000),
                "max_concurrent_locks": MAX_CONCURRENT_LOCKS,
                "locks": {},
                "cross_lock_candidates": cross_lock_candidates,
            }

            # Add per-lock results
            for mac, lock_results in self._results.items():
                summary["locks"][lock_results.lock_name] = {
                    "mac": mac,
                    "attempted": lock_results.attempted,
                    "responses": [f"0x{tid:02X}" for tid in sorted(lock_results.responses)],
                    "timeouts": [f"0x{tid:02X}" for tid in sorted(lock_results.timeouts)],
                    "skipped": [f"0x{tid:02X}" for tid in sorted(lock_results.skipped)],
                    "control_samples": lock_results.control_samples,
                    "candidates": lock_results.candidates,
                }

            # Write summary
            with open(summary_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)

            _LOGGER.info(
                "Battery fuzzing summary written: %s (%d locks, %d cross-lock candidates)",
                summary_path,
                len(self._results),
                len(cross_lock_candidates),
            )

        except Exception as e:
            _LOGGER.error("Failed to write battery fuzzing summary: %s", e)

    def shutdown(self) -> None:
        """Clean shutdown - finalize if needed."""
        if not self._finished and self._results:
            # Note: This is sync, but _finalize is async
            # In practice, _finalize should have been called already
            _LOGGER.warning("Battery fuzzing shutdown before finalization")


# Global singleton instance (created by PushLock)
_global_fuzz_manager: BatteryFuzzManager | None = None


def get_fuzz_manager() -> BatteryFuzzManager | None:
    """Get global fuzzing manager instance."""
    return _global_fuzz_manager


def init_fuzz_manager(
    enabled: bool = True,
    capture_path: str | Path | None = None,
) -> BatteryFuzzManager:
    """Initialize global fuzzing manager.

    Args:
        enabled: If False, fuzzing is disabled
        capture_path: Directory for output files (auto-detected if None)

    Returns:
        BatteryFuzzManager instance
    """
    global _global_fuzz_manager
    if _global_fuzz_manager is None:
        # If no path provided, try to get from protocol capture
        if capture_path is None:
            try:
                from .protocol_capture import _get_writable_capture_path
                capture_path = _get_writable_capture_path()
            except Exception:
                capture_path = Path("/config/yale_captures")

        _global_fuzz_manager = BatteryFuzzManager(
            enabled=enabled,
            capture_path=capture_path,
        )
        _LOGGER.info("Battery fuzzing manager initialized (enabled=%s)", enabled)
    return _global_fuzz_manager
