import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bleak_retry_connector import BLEDevice

from yalexs_ble.const import (
    AuthState,
    AutoLockMode,
    AutoLockState,
    BatteryLevel,
    BatteryState,
    ConnectionInfo,
    DoorStatus,
    LockInfo,
    LockState,
    LockStatus,
)
from yalexs_ble.push import (
    NO_BATTERY_SUPPORT_MODELS,
    PushLock,
    operation_lock,
    retry_bluetooth_connection_error,
)


@pytest.mark.asyncio
async def test_operation_lock():
    """Test the operation_lock function."""

    counter = 0

    class MockPushLock:
        def __init__(self):
            self._operation_lock = asyncio.Lock()

        @property
        def name(self):
            return "lock"

        @operation_lock
        async def do_something(self):
            nonlocal counter
            counter += 1
            await asyncio.sleep(1)
            counter -= 1

    lock = MockPushLock()
    tasks = []
    for _ in range(10):
        tasks.append(asyncio.create_task(lock.do_something()))

    await asyncio.sleep(0)

    for _ in range(10):
        await asyncio.sleep(0)
        assert counter == 1

    for task in tasks:
        task.cancel()
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_operation_lock_with_retry_bluetooth_connection_error():
    """Test the operation_lock and retry_bluetooth_connection_error function."""

    counter = 0

    class MockPushLock:
        def __init__(self):
            self._operation_lock = asyncio.Lock()

        @property
        def name(self):
            return "lock"

        @retry_bluetooth_connection_error
        @operation_lock
        async def do_something(self):
            nonlocal counter
            counter += 1
            try:
                await asyncio.sleep(0.001)
                raise TimeoutError
            finally:
                counter -= 1

    lock = MockPushLock()
    tasks = []
    for _ in range(10):
        tasks.append(asyncio.create_task(lock.do_something()))

    for _ in range(10):
        await asyncio.sleep(0)
        assert counter == 1

    await asyncio.sleep(0.1)
    for _ in range(10):
        await asyncio.sleep(0)
        assert counter == 0

    for task in tasks:
        task.cancel()
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_retry_bluetooth_connection_error_with_operation_lock():
    """Test the operation_lock and retry_bluetooth_connection_error function."""

    counter = 0

    class MockPushLock:
        def __init__(self):
            self._operation_lock = asyncio.Lock()

        @property
        def name(self):
            return "lock"

        @operation_lock
        @retry_bluetooth_connection_error
        async def do_something(self):
            nonlocal counter
            counter += 1
            try:
                await asyncio.sleep(0.001)
                raise TimeoutError
            finally:
                counter -= 1

    lock = MockPushLock()
    tasks = []
    for _ in range(10):
        tasks.append(asyncio.create_task(lock.do_something()))

    for _ in range(10):
        await asyncio.sleep(0)
        assert counter == 1

    await asyncio.sleep(0.1)
    for _ in range(10):
        await asyncio.sleep(0)
        assert counter == 0

    for task in tasks:
        task.cancel()
    await asyncio.sleep(0)


def test_needs_battery_workaround():
    assert "SL-103" in NO_BATTERY_SUPPORT_MODELS
    assert "CERES" in NO_BATTERY_SUPPORT_MODELS
    assert "Yale Linus L2" in NO_BATTERY_SUPPORT_MODELS
    assert "ASL-03" not in NO_BATTERY_SUPPORT_MODELS


@pytest.mark.asyncio
async def test_update_preserves_notify_state():
    """
    Test that _update() does not overwrite lock/door state updated by notify callbacks.

    This reproduces the race condition where:
    1. _update() starts with UNKNOWN state
    2. During battery probe, notify callbacks fire and update state to LOCKED/CLOSED
    3. _update() finishes and should preserve LOCKED/CLOSED (not overwrite with UNKNOWN)
    """
    callback_states = []

    def state_callback(lock_state, lock_info, connection_info):
        callback_states.append(lock_state)

    push_lock = PushLock(
        address="aa:bb:cc:dd:ee:ff",
        key="0800200c9a66",
        key_index=1,
        always_connected=False,
    )
    push_lock.register_callback(state_callback)
    push_lock._name = "Test Lock"

    # Set up lock info to trigger battery probe path
    lock_info = LockInfo(
        manufacturer="Yale",
        model="MD-04I",  # Model that needs battery workaround
        serial="12345",
        firmware="1.8.0",
    )

    # Track when notify callback should fire
    notify_fired = False

    # Mock lock with battery probe that triggers notify callback
    mock_lock = MagicMock()
    mock_lock.lock_info = AsyncMock(return_value=lock_info)

    async def mock_battery_probe():
        """Simulate battery probe that triggers notify callbacks during execution."""
        nonlocal notify_fired

        # Simulate async delay during which notify callback fires
        await asyncio.sleep(0.01)

        # Simulate notify callback firing with LOCKED/CLOSED state
        if not notify_fired:
            notify_fired = True
            push_lock._state_callback([LockStatus.LOCKED, DoorStatus.CLOSED])

        # Return battery data
        return BatteryState(
            voltage=None,
            percentage=75,
            level=BatteryLevel.HIGH,
            source="extended_status_test",
        )

    mock_lock.battery_probe_extended = mock_battery_probe
    mock_lock.auto_lock_status = AsyncMock(
        return_value=AutoLockState(mode=AutoLockMode.OFF, duration=0)
    )
    mock_lock.lock_status = AsyncMock(return_value=LockStatus.LOCKED)

    # Set up the push lock state
    push_lock._lock_info = None  # Force lock_info fetch
    push_lock._running = True
    # Mock advertisement_data to provide connection_info
    from bleak.backends.scanner import AdvertisementData
    push_lock._advertisement_data = AdvertisementData(
        local_name="Test Lock",
        service_data={},
        service_uuids=[],
        rssi=-50,
        manufacturer_data={},
        platform_data=(),
        tx_power=0,
    )

    with patch.object(push_lock, "_ensure_connected", return_value=mock_lock):
        # Run the update
        final_state = await push_lock._update()

        # Verify notify callback fired during update
        assert notify_fired, "Notify callback should have fired during battery probe"

        # The critical assertion: final state must preserve LOCKED/CLOSED from notify
        # NOT revert to UNKNOWN
        assert final_state.lock == LockStatus.LOCKED, (
            f"Expected lock status LOCKED from notify callback, "
            f"got {final_state.lock}. This means _update() overwrote notify state!"
        )
        assert final_state.door == DoorStatus.CLOSED, (
            f"Expected door status CLOSED from notify callback, "
            f"got {final_state.door}. This means _update() overwrote notify state!"
        )

        # Verify battery was also updated
        assert final_state.battery is not None
        assert final_state.battery.percentage == 75
        assert final_state.battery.voltage is None


@pytest.mark.asyncio
async def test_update_partial_updates_preserve_existing_state():
    """
    Test that partial updates (e.g., only battery) preserve other state fields.
    """
    callback_states = []

    def state_callback(lock_state, lock_info, connection_info):
        callback_states.append(lock_state)

    push_lock = PushLock(
        address="aa:bb:cc:dd:ee:ff",
        key="0800200c9a66",
        key_index=1,
        always_connected=False,
    )
    push_lock.register_callback(state_callback)
    push_lock._name = "Test Lock"

    # Set up existing state with known lock/door status
    push_lock._lock_state = LockState(
        lock=LockStatus.LOCKED,
        door=DoorStatus.CLOSED,
        battery=None,
        auth=None,
        auto_lock=None,
        auto_lock_prev=None,
    )

    # Set up lock info for standard battery path (not workaround)
    lock_info = LockInfo(
        manufacturer="August",
        model="ASL-03",
        serial="12345",
        firmware="2.0.0",
    )
    push_lock._lock_info = lock_info

    # Mock lock that only returns battery
    mock_lock = MagicMock()
    mock_lock.battery = AsyncMock(
        return_value=BatteryState(voltage=6.0, percentage=85, level=None, source="standard")
    )

    push_lock._running = True
    # Mock advertisement_data to provide connection_info
    from bleak.backends.scanner import AdvertisementData
    push_lock._advertisement_data = AdvertisementData(
        local_name="Test Lock",
        service_data={},
        service_uuids=[],
        rssi=-50,
        manufacturer_data={},
        platform_data=(),
        tx_power=0,
    )

    with patch.object(push_lock, "_ensure_connected", return_value=mock_lock):
        # Mark that we've already seen lock/door/autolock this session
        push_lock._seen_this_session.add(LockStatus)
        push_lock._seen_this_session.add(DoorStatus)
        push_lock._seen_this_session.add(AutoLockState)

        # Run the update (should only update battery)
        final_state = await push_lock._update()

        # Verify existing lock/door state is preserved
        assert final_state.lock == LockStatus.LOCKED
        assert final_state.door == DoorStatus.CLOSED

        # Verify battery was updated
        assert final_state.battery is not None
        assert final_state.battery.percentage == 85
