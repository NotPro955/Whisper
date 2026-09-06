from dataclasses import dataclass

from .capabilities import FastPairCapabilities, detect_capabilities
from .gatt import GattClient, GattServiceInfo


@dataclass(frozen=True)
class FastPairInspection:
    address: str
    services: list[GattServiceInfo]
    capabilities: FastPairCapabilities


async def inspect_device(address: str) -> FastPairInspection:
    """
    Connect to a BLE device, discover its GATT database, and detect
    Fast Pair capabilities.
    """

    client = GattClient(address)

    try:
        await client.connect()

        services = await client.discover()
        capabilities = detect_capabilities(services)

        return FastPairInspection(
            address=address,
            services=services,
            capabilities=capabilities,
        )

    finally:
        await client.disconnect()
