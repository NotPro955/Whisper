from collections.abc import Awaitable, Callable

from bleak import BleakClient


KBPResponseCallback = Callable[[bytes], Awaitable[None] | None]


class KBPClient:
    """
    Generic Fast Pair Key-Based Pairing GATT transport.

    This class handles only GATT transport:
    - notification/indication listening
    - characteristic capability checks
    - GATT writes

    It does not generate authentication material or bypass
    Fast Pair security.
    """

    def __init__(
        self,
        client: BleakClient,
        characteristic_uuid: str,
        properties: tuple[str, ...],
    ) -> None:
        self.client = client
        self.characteristic_uuid = characteristic_uuid.lower()
        self.properties = tuple(
            property_name.lower()
            for property_name in properties
        )

    @property
    def can_write(self) -> bool:
        return (
            "write" in self.properties
            or "write-without-response" in self.properties
        )

    @property
    def can_notify(self) -> bool:
        return (
            "notify" in self.properties
            or "indicate" in self.properties
        )

    async def listen(
        self,
        callback: KBPResponseCallback,
    ) -> None:
        if not self.client.is_connected:
            raise RuntimeError(
                "BLE device is not connected"
            )

        if not self.can_notify:
            raise RuntimeError(
                "KBP characteristic does not support "
                "notifications or indications"
            )

        async def notification_handler(
            _sender: object,
            data: bytearray,
        ) -> None:
            payload = bytes(data)

            print(
                f"KBP response received: "
                f"{len(payload)} bytes"
            )

            result = callback(payload)

            if result is not None:
                await result

        await self.client.start_notify(
            self.characteristic_uuid,
            notification_handler,
        )

    async def stop_listening(self) -> None:
        if not self.client.is_connected:
            return

        try:
            await self.client.stop_notify(
                self.characteristic_uuid
            )
        except Exception:
            pass

    async def write(self, payload: bytes) -> None:
        if not self.client.is_connected:
            raise RuntimeError(
                "BLE device is not connected"
            )

        if not self.can_write:
            raise RuntimeError(
                "KBP characteristic does not support writing"
            )

        await self.client.write_gatt_char(
            self.characteristic_uuid,
            payload,
            response="write" in self.properties,
        )
 
