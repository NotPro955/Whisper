from dataclasses import dataclass

from bleak import BleakScanner

from .advertisement import parse_fast_pair_service_data


@dataclass
class FastPairDevice:
    name: str
    address: str
    rssi: int | None
    model_id: int
    flags: int
    raw_data: bytes
    fast_pair_advertising: bool


async def scan(duration: float = 10.0) -> list[FastPairDevice]:
    """
    Scan for BLE devices advertising the Google Fast Pair service.

    Scanning only observes advertisements. It does not connect to
    or modify any device.
    """

    print(f"Scanning for Fast Pair devices for {duration:g} seconds...")
    print()

    discovered = await BleakScanner.discover(
        timeout=duration,
        return_adv=True,
    )

    found: list[FastPairDevice] = []

    for address, (device, advertisement) in discovered.items():
        parsed = parse_fast_pair_service_data(
            advertisement.service_data
        )

        if parsed is None:
            continue

        found.append(
            FastPairDevice(
                name=device.name or advertisement.local_name or "Unknown",
                address=address,
                rssi=advertisement.rssi,
                model_id=parsed.model_id,
                flags=parsed.flags,
                raw_data=parsed.raw_data,
                fast_pair_advertising=True,
            )
        )

    return found
