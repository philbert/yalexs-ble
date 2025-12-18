"""Tests for battery fuzzing."""

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from src.yalexs_ble.battery_fuzz import (
    BatteryFuzzManager,
    FUZZ_START,
    FUZZ_END,
    KNOWN_STATUS_TYPES,
)


@pytest.mark.asyncio
async def test_battery_fuzz_manager_init():
    """Test BatteryFuzzManager initialization."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = BatteryFuzzManager(enabled=True, capture_path=tmpdir)
        assert manager._enabled
        assert manager._capture_path == Path(tmpdir)
        assert not manager._fuzzed_macs
        assert not manager._results


@pytest.mark.asyncio
async def test_battery_fuzz_should_fuzz():
    """Test should_fuzz logic."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = BatteryFuzzManager(enabled=True, capture_path=tmpdir)

        mac = "AA:BB:CC:DD:EE:FF"
        assert manager.should_fuzz(mac)

        # Mark as fuzzed
        manager._fuzzed_macs.add(mac)
        assert not manager.should_fuzz(mac)


@pytest.mark.asyncio
async def test_battery_fuzz_disabled():
    """Test fuzzing when disabled."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = BatteryFuzzManager(enabled=False, capture_path=tmpdir)

        mac = "AA:BB:CC:DD:EE:FF"
        assert not manager.should_fuzz(mac)


@pytest.mark.asyncio
async def test_battery_fuzz_known_types():
    """Test that known status types are defined."""
    assert 0x02 in KNOWN_STATUS_TYPES  # LOCK_ONLY
    assert 0x0F in KNOWN_STATUS_TYPES  # BATTERY
    assert 0x2E in KNOWN_STATUS_TYPES  # DOOR_ONLY
    assert 0x2F in KNOWN_STATUS_TYPES  # DOOR_AND_LOCK


@pytest.mark.asyncio
async def test_battery_fuzz_range():
    """Test fuzz range is valid."""
    assert FUZZ_START == 0x00
    assert FUZZ_END == 0x3F
    assert FUZZ_START < FUZZ_END


@pytest.mark.asyncio
async def test_battery_fuzz_mock_responses():
    """Test fuzzing with mock send function."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = BatteryFuzzManager(enabled=True, capture_path=tmpdir)

        mac = "AA:BB:CC:DD:EE:FF"
        lock_name = "Test Lock"

        # Mock send function that responds to specific type_ids
        response_type_ids = {0x0F, 0x10, 0x20}  # BATTERY control + test candidates

        def mock_build_command(opcode: int, type_id: int) -> bytearray:
            """Mock command builder."""
            # Build a simple command with type_id at byte 4
            cmd = bytearray(18)
            cmd[0] = 0xEE
            cmd[1] = opcode
            cmd[4] = type_id
            return cmd

        async def mock_send(command: bytes) -> bytes:
            """Mock send function."""
            # Extract type_id from command (byte 4)
            if len(command) >= 5:
                type_id = command[4]
                if type_id in response_type_ids:
                    # Return mock response
                    return bytes([0xBB, 0x02, 0x00, 0x00, type_id, 0x01, 0x02, 0x00, 0x00])
            # Timeout (raise TimeoutError)
            raise asyncio.TimeoutError()

        # Run fuzzing
        await manager.fuzz_lock(
            mac=mac,
            lock_name=lock_name,
            send_command_func=mock_send,
            build_command_func=mock_build_command,
        )

        # Check results
        assert mac in manager._results
        results = manager._results[mac]
        assert results.lock_name == lock_name
        assert results.mac == mac
        # We should get responses for 0x10, 0x20, and BATTERY (0x0F) control sample
        assert len(results.responses) == 3
        assert 0x10 in results.responses
        assert 0x20 in results.responses
        assert 0x0F in results.responses  # BATTERY control sample
        # Should skip LOCK_ONLY, DOOR_ONLY, DOOR_AND_LOCK (not BATTERY)
        assert len(results.skipped) == len(KNOWN_STATUS_TYPES) - 1  # All except BATTERY

        # Check summary file was written
        summary_files = list(Path(tmpdir).glob("battery_fuzz_summary_*.json"))
        assert len(summary_files) == 1

        with open(summary_files[0]) as f:
            summary = json.load(f)

        assert summary["range"] == f"0x{FUZZ_START:02X}-0x{FUZZ_END:02X}"
        assert "Test Lock" in summary["locks"]
        assert summary["locks"]["Test Lock"]["mac"] == mac
        assert len(summary["locks"]["Test Lock"]["responses"]) == 3
        # Check that BATTERY is in control_samples, not candidates
        assert "0x0F" in summary["locks"]["Test Lock"]["control_samples"]
        assert "0x10" in summary["locks"]["Test Lock"]["candidates"]
        assert "0x20" in summary["locks"]["Test Lock"]["candidates"]
