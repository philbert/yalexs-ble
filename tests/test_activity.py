"""Tests for the activity manager."""

import asyncio
import contextlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from yalexs_ble.activity import ActivityManager
from yalexs_ble.const import (
    LOCK_ACTIVITY_POLL_RETRIES,
    LOCK_ACTIVITY_POLL_RETRY_EXPONENTIAL_BACKOFF_SECONDS,
    ConnectionInfo,
    DoorActivity,
    DoorStatus,
    LockActivity,
    LockActivityValue,
    LockInfo,
    LockOperationSource,
    LockStatus,
)

TEST_LOCK_INFO = LockInfo(
    manufacturer="August",
    model="ASL-03",
    serial="12345",
    firmware="2.0.0",
)
TEST_CONNECTION_INFO = ConnectionInfo(rssi=-60)
TEST_TIMESTAMP = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
# A regression that leaves a poll running should fail the suite, not hang it.
TIMEOUT = 1


def door_activity(status: DoorStatus = DoorStatus.OPENED) -> DoorActivity:
    """Build a door activity for assertions."""
    return DoorActivity(timestamp=TEST_TIMESTAMP, status=status)


def lock_activity(status: LockStatus = LockStatus.LOCKED) -> LockActivity:
    """Build a lock activity for assertions."""
    return LockActivity(
        timestamp=TEST_TIMESTAMP,
        status=status,
        source=LockOperationSource.MANUAL,
    )


class FakeTimerHandle:
    """Stand-in for asyncio.TimerHandle that records its own state.

    ActivityManager only ever calls cancel() on the handle it gets back from
    call_later, so recording cancellation is enough to assert on rescheduling.
    """

    def __init__(self, delay: float, callback: Callable[[], None]) -> None:
        self.delay = delay
        self.callback = callback
        self.cancelled = False
        self.fired = False

    def cancel(self) -> None:
        self.cancelled = True


class FakeLoop:
    """Records call_later scheduling so tests can fire timers by hand.

    Real timers would make the backoff assertions take 105 seconds of wall
    clock, so the loop is faked rather than the clock.
    """

    def __init__(self) -> None:
        self.timers: list[FakeTimerHandle] = []

    def call_later(
        self, delay: float, callback: Callable[..., None], *args: Any
    ) -> FakeTimerHandle:
        handle = FakeTimerHandle(delay, lambda: callback(*args))
        self.timers.append(handle)
        return handle

    @property
    def delays(self) -> list[float]:
        """Every delay scheduled so far, in order."""
        return [timer.delay for timer in self.timers]

    @property
    def waiting(self) -> list[FakeTimerHandle]:
        """Timers that have neither fired nor been cancelled."""
        return [t for t in self.timers if not t.fired and not t.cancelled]


class FakeBridge:
    """Minimal LockBridge implementation backed by a mock Lock."""

    def __init__(self, loop: FakeLoop, lock: MagicMock) -> None:
        self.name = "Front Door"
        self.lock_info: LockInfo | None = TEST_LOCK_INFO
        self.connection_info: ConnectionInfo | None = TEST_CONNECTION_INFO
        self.loop = loop
        self.ensure_connected_calls = 0
        # Set gate to park a poll inside ensure_connected; reached_connect
        # lets a test wait until the poll is genuinely in flight.
        self.gate: asyncio.Event | None = None
        self.reached_connect = asyncio.Event()
        self._lock = lock

    async def ensure_connected(self) -> MagicMock:
        self.ensure_connected_calls += 1
        self.reached_connect.set()
        if self.gate is not None:
            await self.gate.wait()
        return self._lock


@pytest.fixture
def lock() -> MagicMock:
    """A Lock whose lock_activity reports no activity by default."""
    lock = MagicMock()
    lock.lock_activity = AsyncMock(return_value=None)
    return lock


@pytest.fixture
def loop() -> FakeLoop:
    return FakeLoop()


@pytest.fixture
def bridge(loop: FakeLoop, lock: MagicMock) -> FakeBridge:
    return FakeBridge(loop, lock)


@pytest.fixture
def manager(bridge: FakeBridge) -> ActivityManager:
    return ActivityManager(bridge)


async def fire_next_timer(loop: FakeLoop, manager: ActivityManager) -> None:
    """Fire the earliest waiting timer and await the poll it starts."""
    waiting = loop.waiting
    assert waiting, "expected a scheduled timer"
    timer = waiting[0]
    timer.fired = True
    timer.callback()
    if task := manager._activity_poll_task:
        async with asyncio.timeout(TIMEOUT):
            await task


async def drain_timers(
    loop: FakeLoop, manager: ActivityManager, limit: int = 10
) -> None:
    """Fire timers until scheduling settles, awaiting each poll."""
    for _ in range(limit):
        if not loop.waiting:
            return
        await fire_next_timer(loop, manager)
    raise AssertionError("activity polling never stopped rescheduling")


def test_schedule_activity_poll_without_callbacks_does_nothing(
    manager: ActivityManager, loop: FakeLoop
) -> None:
    """Activity is left for the Yale/August app when nothing is listening."""
    manager.schedule_activity_poll(15)

    assert loop.timers == []


def test_register_callback_returns_working_unsubscribe(
    manager: ActivityManager, loop: FakeLoop
) -> None:
    unsubscribe = manager.register_activity_callback(MagicMock())
    manager.schedule_activity_poll(15)
    assert loop.delays == [15]

    unsubscribe()
    manager.schedule_activity_poll(15)

    assert loop.delays == [15]


def test_reschedule_false_keeps_the_pending_timer(
    manager: ActivityManager, loop: FakeLoop
) -> None:
    """A poll already on the books wins over a later reschedule=False call."""
    manager.register_activity_callback(MagicMock())
    manager.schedule_activity_poll(30)

    manager.schedule_activity_poll(5, reschedule=False)

    assert loop.delays == [30]
    assert loop.timers[0].cancelled is False


def test_reschedule_false_still_schedules_when_idle(
    manager: ActivityManager, loop: FakeLoop
) -> None:
    manager.register_activity_callback(MagicMock())

    manager.schedule_activity_poll(5, reschedule=False)

    assert loop.delays == [5]


def test_reschedule_true_replaces_the_pending_timer(
    manager: ActivityManager, loop: FakeLoop
) -> None:
    manager.register_activity_callback(MagicMock())
    manager.schedule_activity_poll(30)

    manager.schedule_activity_poll(5)

    assert loop.delays == [30, 5]
    assert loop.timers[0].cancelled is True


@pytest.mark.asyncio
async def test_request_update_polls_immediately_without_retrying(
    manager: ActivityManager, loop: FakeLoop
) -> None:
    """request_update asks for one immediate attempt and no retries."""
    manager.register_activity_callback(MagicMock(), request_update=True)
    assert loop.delays == [0]

    await drain_timers(loop, manager)

    assert loop.delays == [0]


@pytest.mark.asyncio
async def test_retries_back_off_exponentially(
    manager: ActivityManager, loop: FakeLoop
) -> None:
    """A poll that finds nothing retries on a 15 -> 30 -> 60 second backoff."""
    assert LOCK_ACTIVITY_POLL_RETRY_EXPONENTIAL_BACKOFF_SECONDS == 15
    assert LOCK_ACTIVITY_POLL_RETRIES == 3
    manager.register_activity_callback(MagicMock())

    manager.schedule_activity_poll(0)
    await drain_timers(loop, manager)

    assert loop.delays == [0, 15, 30, 60]


@pytest.mark.asyncio
async def test_polling_stops_after_max_retries(
    manager: ActivityManager, loop: FakeLoop, bridge: FakeBridge
) -> None:
    manager.register_activity_callback(MagicMock())

    manager.schedule_activity_poll(0)
    await drain_timers(loop, manager)

    assert bridge.ensure_connected_calls == LOCK_ACTIVITY_POLL_RETRIES + 1


@pytest.mark.asyncio
async def test_custom_backoff_and_max_retries_are_respected(
    manager: ActivityManager, loop: FakeLoop
) -> None:
    manager.register_activity_callback(MagicMock())

    manager.schedule_activity_poll(0, max_retries=2, backoff=5)
    await drain_timers(loop, manager)

    assert loop.delays == [0, 5, 10]


@pytest.mark.asyncio
async def test_poll_drains_activity_until_exhausted(
    manager: ActivityManager, loop: FakeLoop, lock: MagicMock
) -> None:
    """Activity keeps being fetched until the lock reports none left."""
    lock.lock_activity = AsyncMock(side_effect=[door_activity(), lock_activity(), None])
    manager.register_activity_callback(MagicMock())

    manager.schedule_activity_poll(0)
    await drain_timers(loop, manager)

    assert lock.lock_activity.await_count == 3
    assert loop.delays == [0]


@pytest.mark.asyncio
async def test_poll_aborts_when_callbacks_removed_before_it_runs(
    manager: ActivityManager, loop: FakeLoop, bridge: FakeBridge
) -> None:
    """Unsubscribing between scheduling and firing must not connect."""
    unsubscribe = manager.register_activity_callback(MagicMock())
    manager.schedule_activity_poll(0)

    unsubscribe()
    await fire_next_timer(loop, manager)

    assert bridge.ensure_connected_calls == 0


@pytest.mark.asyncio
async def test_poll_errors_are_swallowed_and_not_retried(
    manager: ActivityManager,
    loop: FakeLoop,
    lock: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="yalexs_ble.activity")
    lock.lock_activity = AsyncMock(side_effect=RuntimeError("boom"))
    manager.register_activity_callback(MagicMock())

    manager.schedule_activity_poll(0)
    await fire_next_timer(loop, manager)

    assert "Unknown error performing deferred activity update" in caplog.text
    assert loop.delays == [0]


@pytest.mark.asyncio
async def test_deferred_poll_skipped_while_one_is_in_flight(
    manager: ActivityManager, loop: FakeLoop, bridge: FakeBridge
) -> None:
    """A second timer firing must not start a competing poll."""
    bridge.gate = asyncio.Event()
    manager.register_activity_callback(MagicMock())

    manager.schedule_activity_poll(0)
    loop.timers[0].fired = True
    loop.timers[0].callback()
    in_flight = manager._activity_poll_task
    async with asyncio.timeout(TIMEOUT):
        await bridge.reached_connect.wait()

    manager.schedule_activity_poll(15)
    loop.timers[1].fired = True
    loop.timers[1].callback()

    assert manager._activity_poll_task is in_flight
    assert bridge.ensure_connected_calls == 1

    bridge.gate.set()
    assert in_flight is not None
    async with asyncio.timeout(TIMEOUT):
        await in_flight


@pytest.mark.asyncio
async def test_forced_disconnect_cancels_an_in_flight_poll(
    manager: ActivityManager, loop: FakeLoop, bridge: FakeBridge
) -> None:
    bridge.gate = asyncio.Event()
    manager.register_activity_callback(MagicMock())

    manager.schedule_activity_poll(0)
    loop.timers[0].fired = True
    loop.timers[0].callback()
    task = manager._activity_poll_task
    async with asyncio.timeout(TIMEOUT):
        await bridge.reached_connect.wait()

    # execute_forced_disconnect awaits the task it just cancelled, so it
    # re-raises CancelledError; push.py suppresses that at the call site.
    # Suppressing here keeps this test honest either way.
    with contextlib.suppress(asyncio.CancelledError):
        async with asyncio.timeout(TIMEOUT):
            await manager.execute_forced_disconnect()

    assert task is not None
    assert task.cancelled()
    assert manager._activity_poll_task is None


@pytest.mark.asyncio
async def test_forced_disconnect_without_a_poll_is_a_noop(
    manager: ActivityManager,
) -> None:
    await manager.execute_forced_disconnect()

    assert manager._activity_poll_task is None


@pytest.mark.asyncio
async def test_forced_disconnect_leaves_a_finished_poll_alone(
    manager: ActivityManager, loop: FakeLoop
) -> None:
    manager.register_activity_callback(MagicMock())
    manager.schedule_activity_poll(0, max_retries=0)
    await fire_next_timer(loop, manager)
    finished = manager._activity_poll_task

    await manager.execute_forced_disconnect()

    assert manager._activity_poll_task is finished


@pytest.mark.parametrize("activity", [door_activity(), lock_activity()])
def test_handle_activities_invokes_every_callback(
    manager: ActivityManager, activity: LockActivityValue
) -> None:
    first, second = MagicMock(), MagicMock()
    manager.register_activity_callback(first)
    manager.register_activity_callback(second)

    manager.handle_activities([activity])

    for callback in (first, second):
        callback.assert_called_once_with(activity, TEST_LOCK_INFO, TEST_CONNECTION_INFO)


def test_handle_activities_forwards_each_activity_in_order(
    manager: ActivityManager,
) -> None:
    callback = MagicMock()
    manager.register_activity_callback(callback)
    activities: list[LockActivityValue] = [
        door_activity(),
        lock_activity(),
        door_activity(DoorStatus.CLOSED),
    ]

    manager.handle_activities(activities)

    assert [c.args[0] for c in callback.call_args_list] == activities


def test_handle_activities_without_callbacks_is_a_noop(
    manager: ActivityManager, bridge: FakeBridge
) -> None:
    """The lock_info/connection_info asserts sit behind the callback guard."""
    bridge.lock_info = None
    bridge.connection_info = None

    manager.handle_activities([door_activity()])


def test_one_failing_callback_does_not_stop_the_others(
    manager: ActivityManager, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="yalexs_ble.activity")
    failing = MagicMock(side_effect=RuntimeError("boom"))
    healthy = MagicMock()
    manager.register_activity_callback(failing)
    manager.register_activity_callback(healthy)
    activity = door_activity()

    manager.handle_activities([activity])

    healthy.assert_called_once_with(activity, TEST_LOCK_INFO, TEST_CONNECTION_INFO)
    assert "Error calling activity callback" in caplog.text
