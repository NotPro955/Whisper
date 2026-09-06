from dataclasses import dataclass

from bleak import BleakClient


@dataclass(frozen=True)
class GattCharacteristicInfo:
    uuid: str
    properties: tuple[str, ...]


@dataclass(frozen=True)
class GattServiceInfo:
    uuid: str
    characteristics: tuple[GattCharacteristicInfo, ...]


class GattClient:
    """
    Generic BLE GATT discovery.

    This class does not assume a particular earbud manufacturer,
    model, or characteristic layout.
    """

    def __init__(self, address: str):
        self.address = address
        self.client: BleakClient | None = None

    async def connect(self) -> None:
        if self.client and self.client.is_connected:
            return

        self.client = BleakClient(self.address)
        await self.client.connect()

    async def disconnect(self) -> None:
        if self.client and self.client.is_connected:
            await self.client.disconnect()

    @property
    def connected(self) -> bool:
        return bool(
            self.client and self.client.is_connected
        )

    async def discover(self) -> list[GattServiceInfo]:
        if not self.client or not self.client.is_connected:
            raise RuntimeError("BLE device is not connected")

        services: list[GattServiceInfo] = []

        for service in self.client.services:
            characteristics = tuple(
                GattCharacteristicInfo(
                    uuid=characteristic.uuid.lower(),
                    properties=tuple(characteristic.properties),
                )
                for characteristic in service.characteristics
            )

            services.append(
                GattServiceInfo(
                    uuid=service.uuid.lower(),
                    characteristics=characteristics,
                )
            )

        return services