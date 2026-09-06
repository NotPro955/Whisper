import asyncio
import shutil


class BlueZError(RuntimeError):
    """Raised when a BlueZ operation fails."""


class BlueZ:
    """
    Small wrapper around bluetoothctl.

    This provides basic Bluetooth-controller operations while keeping
    bluetoothctl-specific details out of the rest of the application.
    """

    @staticmethod
    def available() -> bool:
        """Return True if bluetoothctl is installed."""
        return shutil.which("bluetoothctl") is not None

    async def _run(self, *arguments: str) -> str:
        if not self.available():
            raise BlueZError(
                "bluetoothctl was not found. "
                "Install bluez-utils."
            )

        process = await asyncio.create_subprocess_exec(
            "bluetoothctl",
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        output = stdout.decode(errors="replace").strip()
        error = stderr.decode(errors="replace").strip()

        if process.returncode != 0:
            raise BlueZError(
                error or output or
                f"bluetoothctl exited with code {process.returncode}"
            )

        return output

    async def power_on(self) -> str:
        """Power on the default Bluetooth controller."""
        return await self._run("power", "on")

    async def show(self) -> str:
        """Return information about the Bluetooth controller."""
        return await self._run("show")

    async def list_controllers(self) -> str:
        """Return the available Bluetooth controllers."""
        return await self._run("list")

    async def connect(self, address: str) -> str:
        """Connect to a Bluetooth device using its selected address."""

        if not address:
            raise BlueZError(
                "Bluetooth device address is empty."
            )

        return await self._run("connect", address)
