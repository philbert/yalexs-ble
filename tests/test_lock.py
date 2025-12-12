import asyncio
import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bleak_retry_connector import BLEDevice

from yalexs_ble.const import (
    BatteryLevel,
    BatteryState,
    LockOperationRemoteType,
    LockOperationSource,
    StatusType,
)
from yalexs_ble.lock import Lock


def test_create_lock():
    Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock"),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )


@pytest.mark.asyncio
async def test_connection_canceled_on_disconnect():
    disconnect_mock = AsyncMock()
    mock_client = MagicMock(connected=True, disconnect=disconnect_mock)
    lock = Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock", delegate=""),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )
    lock.client = mock_client

    async def connect_and_wait():
        await lock.connect()
        await asyncio.sleep(2)

    with patch("yalexs_ble.lock.Lock.connect"):
        task = asyncio.create_task(connect_and_wait())
        await asyncio.sleep(0)
        task.cancel()

    with contextlib.suppress(asyncio.CancelledError):
        await task

    assert task.cancelled() is True


def test_parse_operation_source():
    """Test parsing operation source and remote type."""
    lock = Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock"),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )

    # Test remote source with BLE type
    source, remote_type = lock._parse_operation_source(0x00, 0x03)
    assert source is LockOperationSource.REMOTE
    assert remote_type is LockOperationRemoteType.BLE

    # Test manual source (remote_type should be None)
    source, remote_type = lock._parse_operation_source(0x01, 0x03)
    assert source is LockOperationSource.MANUAL
    assert remote_type is None

    # Test auto lock source (remote_type should be None)
    source, remote_type = lock._parse_operation_source(0x05, 0x00)
    assert source is LockOperationSource.AUTO_LOCK
    assert remote_type is None

    # Test PIN source (remote_type should be None)
    source, remote_type = lock._parse_operation_source(0x0B, 0x03)
    assert source is LockOperationSource.PIN
    assert remote_type is None

    # Test unknown source
    source, remote_type = lock._parse_operation_source(0x99, 0x03)
    assert source is LockOperationSource.UNKNOWN
    assert remote_type is None

    # Test remote source with unknown remote type
    source, remote_type = lock._parse_operation_source(0x00, 0x99)
    assert source is LockOperationSource.REMOTE
    assert remote_type is LockOperationRemoteType.UNKNOWN

    # Test remote source with UNKNOWN (0x00) remote type
    source, remote_type = lock._parse_operation_source(0x00, 0x00)
    assert source is LockOperationSource.REMOTE
    assert remote_type is LockOperationRemoteType.UNKNOWN


def test_try_parse_extended_battery_percentage():
    """Test parsing battery from extended status response with percentage value."""
    lock = Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock"),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )

    # Simulated extended status response with battery percentage at offset 0x08
    # bb 02 XX XX 2F 00 00 00 [4B] ... (75%)
    response = bytes.fromhex("bb02001a2f0000004b000000000000000200")
    battery = lock._try_parse_extended_battery(response, StatusType.DOOR_AND_LOCK.value)

    assert battery is not None
    assert battery.percentage == 75
    assert battery.voltage is None  # Extended status has no voltage data
    assert battery.level is None
    assert "extended_status_0x2f" in battery.source


def test_try_parse_extended_battery_enum():
    """Test parsing battery from extended status response with enum level value."""
    lock = Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock"),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )

    # Simulated extended status response with battery enum at offset 0x08
    # bb 02 XX XX 2F 00 00 00 [03] ... (level 3 = HIGH, 75%)
    response = bytes.fromhex("bb02001a2f00000003000000000000000200")
    battery = lock._try_parse_extended_battery(response, StatusType.DOOR_AND_LOCK.value)

    assert battery is not None
    assert battery.level == BatteryLevel.HIGH
    assert battery.percentage == 75
    assert battery.voltage is None  # Extended status has no voltage data
    assert "enum" in battery.source


def test_try_parse_extended_battery_no_data():
    """Test parsing battery from short response returns None."""
    lock = Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock"),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )

    # Short response (less than 0x10 bytes)
    response = bytes.fromhex("bb02001a2f")
    battery = lock._try_parse_extended_battery(response, StatusType.DOOR_AND_LOCK.value)

    assert battery is None


@pytest.mark.asyncio
async def test_battery_probe_extended_stops_on_timeout():
    """Test that battery probe stops after first timeout."""
    lock = Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock"),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )
    # Properly set up connected state
    mock_client = MagicMock()
    mock_client.is_connected = True
    lock.client = mock_client
    lock.session = MagicMock()
    lock.secure_session = MagicMock()
    lock._disconnected = False

    # Mock _execute_command to timeout on first call
    execute_count = 0

    async def mock_execute(*args, **kwargs):
        nonlocal execute_count
        execute_count += 1
        raise asyncio.TimeoutError("Probe timeout")

    with patch.object(lock, "_execute_command", side_effect=mock_execute):
        battery = await lock.battery_probe_extended()

    # Should have stopped after first timeout
    assert battery is None
    assert execute_count == 1


@pytest.mark.asyncio
async def test_battery_probe_extended_returns_first_success():
    """Test that battery probe returns first successful result."""
    lock = Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock"),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )
    # Properly set up connected state
    mock_client = MagicMock()
    mock_client.is_connected = True
    lock.client = mock_client
    lock.session = MagicMock()
    lock.secure_session = MagicMock()
    lock._disconnected = False

    # First probe fails, second succeeds
    call_count = 0

    async def mock_execute(opcode, status_type, command_name):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call: return response with no plausible battery data (all invalid bytes)
            return bytes.fromhex("bb02001a2f000000ffffffffffffffff0200")
        else:
            # Second call: return response with battery percentage (0x4B = 75 at offset 0x08)
            return bytes.fromhex("bb02001a2d0000004b000000000000000200")

    with patch.object(lock, "_execute_command", side_effect=mock_execute):
        battery = await lock.battery_probe_extended()

    assert battery is not None
    assert battery.percentage == 75
    assert call_count == 2  # Should have tried 2 probes


def test_enum_battery_has_no_voltage():
    """Test that enum-derived battery has voltage=None, not 0.0."""
    lock = Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock"),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )

    # Battery from enum should have voltage=None
    response = bytes.fromhex("bb02001a2f00000003000000000000000200")
    battery = lock._try_parse_extended_battery(response, StatusType.DOOR_AND_LOCK.value)

    assert battery is not None
    assert battery.voltage is None  # Not 0.0!
    assert battery.level == BatteryLevel.HIGH


def test_percentage_battery_has_no_voltage():
    """Test that percentage-derived battery from extended status has voltage=None."""
    lock = Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock"),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )

    # Battery from percentage should also have voltage=None
    response = bytes.fromhex("bb02001a2f0000004b000000000000000200")
    battery = lock._try_parse_extended_battery(response, StatusType.DOOR_AND_LOCK.value)

    assert battery is not None
    assert battery.voltage is None  # Not 0.0!
    assert battery.percentage == 75


def test_battery_from_enum_levels():
    """Test battery percentage mapping from enum levels."""
    lock = Lock(
        lambda: BLEDevice("aa:bb:cc:dd:ee:ff", "lock"),
        "0800200c9a66",
        1,
        "mylock",
        lambda _: None,
    )

    # Test all enum levels
    test_cases = [
        (0, BatteryLevel.CRITICAL, 5),
        (1, BatteryLevel.LOW, 25),
        (2, BatteryLevel.MEDIUM, 50),
        (3, BatteryLevel.HIGH, 75),
        (4, BatteryLevel.HIGH, 90),
        (5, BatteryLevel.HIGH, 100),
    ]

    for enum_value, expected_level, expected_pct in test_cases:
        response = bytes.fromhex(f"bb02001a2f00000000000000000000000200")
        # Set the enum value at offset 0x08
        response_list = list(response)
        response_list[0x08] = enum_value
        response = bytes(response_list)

        battery = lock._try_parse_extended_battery(response, StatusType.DOOR_AND_LOCK.value)

        assert battery is not None, f"Failed to parse enum value {enum_value}"
        assert battery.level == expected_level, f"Enum {enum_value}: expected {expected_level}, got {battery.level}"
        assert battery.percentage == expected_pct, f"Enum {enum_value}: expected {expected_pct}%, got {battery.percentage}%"
        assert battery.voltage is None
