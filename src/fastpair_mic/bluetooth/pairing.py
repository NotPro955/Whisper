from .bluez import BlueZ, BlueZError


class PairingError(RuntimeError):
    """Raised when Bluetooth pairing fails."""


class BluetoothPairing:
    """
    Handles normal user-authorized Bluetooth pairing through BlueZ.

    Fast Pair protocol operations are intentionally kept out of this
    class.
    """

    def __init__(self, bluez: BlueZ | None = None):
        self.bluez = bluez or BlueZ()

    async def pair(self, address: str) -> str:
        """
        Pair with a Bluetooth device using bluetoothctl.

        The address is supplied by the user/device discovery layer;
        this class does not contain any hard-coded device addresses.
        """

        if not address:
            raise PairingError("Bluetooth device address is empty.")

        try:
            output = await self.bluez._run("pair", address)
        except BlueZError as exc:
            raise PairingError(str(exc)) from exc

        return output

    async def trust(self, address: str) -> str:
        """Mark a successfully paired device as trusted."""

        if not address:
            raise PairingError("Bluetooth device address is empty.")

        try:
            return await self.bluez._run("trust", address)
        except BlueZError as exc:
            raise PairingError(str(exc)) from exc

    async def remove(self, address: str) -> str:
        """Remove a device from BlueZ's paired-device database."""

        if not address:
            raise PairingError("Bluetooth device address is empty.")

        try:
            return await self.bluez._run("remove", address)
        except BlueZError as exc:
            raise PairingError(str(exc)) from exc

