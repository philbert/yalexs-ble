from __future__ import annotations

from asyncio import timeout as asyncio_timeout  # noqa: F401
from dataclasses import dataclass

from bleak import BleakError
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

UNIQUE_LOCAL_NAME_LEN = 7


def _simple_checksum(buf: bytes) -> int:
    cs = 0
    for i in range(0x12):
        cs = (cs + buf[i]) & 0xFF

    return (-cs) & 0xFF


def _bytes_to_int(buffer: bytes) -> int:
    """Convert a byte buffer to an integer."""
    return int.from_bytes(buffer, byteorder="little", signed=False)


def _int_to_bytes(value: int, length: int) -> bytes:
    """Convert an integer to a byte buffer."""
    if length < 1 or length > 8:
        raise ValueError("Length must be between 1 and 8 bytes.")
    return value.to_bytes(length, byteorder="little", signed=False)


def _security_checksum(buffer: bytes) -> int:
    val1 = _bytes_to_int(buffer[0x00:0x04])
    val2 = _bytes_to_int(buffer[0x04:0x08])
    val3 = _bytes_to_int(buffer[0x08:0x12])

    return (0 - (val1 + val2 + val3)) & 0xFFFFFFFF


def _copy(dest: bytearray, src: bytes, destLocation: int = 0) -> None:
    dest[destLocation : (destLocation + len(src))] = src


def serial_to_local_name(serial: str) -> str:
    """Convert a serial to a local name."""
    return f"{serial[0:2]}{serial[-5:]}"


def local_name_to_serial(serial: str) -> str:
    """Convert a local name to a serial."""
    return f"{serial[0:2]}XXX{serial[2:]}"


def is_key_error(error: Exception) -> bool:
    """Check if the error likely due to the wrong key."""
    err_str = str(error)
    return bool(
        isinstance(error, BleakError)
        and ("Unlikely Error" in err_str or "error=133" in err_str)
    )


def is_disconnected_error(error: Exception) -> bool:
    """Check if the error is a disconnected error."""
    err_str = str(error)
    return is_key_error(error) or bool(
        isinstance(error, BleakError)
        and (
            "disconnect" in err_str
            or "Connection Rejected Due To Security Reasons" in err_str
        )
    )


@dataclass
class ValidatedLockConfig:
    """A validated lock configuration."""

    name: str
    address: str
    serial: str
    key: str
    slot: int

    @property
    def local_name(self) -> str:
        """Get the local name from the serial."""
        return serial_to_local_name(self.serial)


def unique_id_from_device_adv(
    device: BLEDevice, advertisement: AdvertisementData
) -> str:
    """Get the unique id from the advertisement."""
    return unique_id_from_local_name_address(advertisement.local_name, device.address)


def unique_id_from_local_name_address(local_name: str, address: str) -> str:
    """Get the unique id from the advertisement."""
    return local_name if local_name_is_unique(local_name) else address


def local_name_is_unique(local_name: str | None) -> bool:
    """Check if the local name is unique."""
    return bool(local_name and len(local_name) == UNIQUE_LOCAL_NAME_LEN)


def decode_battery_from_manufacturer_data(mfr_data: bytes) -> tuple[int | None, str]:
    """
    Attempt to decode battery information from Yale manufacturer data (ID 0x01D1 = 465).

    This is a best-effort decoder for locks like MD-04I that may advertise
    battery information in manufacturer-specific data. The exact format is not
    fully documented, so this function is structured to be easily updated as
    we learn more about the format.

    Args:
        mfr_data: Raw manufacturer data payload from advertisements

    Returns:
        Tuple of (battery_percentage, raw_hex_string)
        - battery_percentage: Estimated percentage (0-100) or None if unknown
        - raw_hex_string: Hex representation for diagnostics

    Example observed data:
        0x01000002FF783A111A0B25DB4F3E1AD56DCAD17
    """
    raw_hex = mfr_data.hex()

    if len(mfr_data) < 2:
        return None, raw_hex

    # For now, we don't have enough information to reliably decode battery
    # from manufacturer data. We'll log the raw data for future analysis.
    # Potential battery indicators to investigate:
    # - Byte 0-1: Header/flags
    # - Byte 2-3: Possible status fields
    # - Look for small values (0-100 or 0-5) that might indicate battery

    # Heuristic: look for bytes that could be battery percentage (0-100)
    # or level enum (0-5) in the first few bytes
    for i in range(min(len(mfr_data), 10)):
        value = mfr_data[i]
        # If we find a value between 0-100 that's not 0xFF, it might be battery
        if 0 < value <= 100 and value != 0xFF:
            # This is speculative - we'd need real-world data to confirm
            # For now, just return None to indicate we don't know
            pass

    # Return None for battery percentage until we can decode the format
    return None, raw_hex
