from dataclasses import dataclass


@dataclass
class BluetoothDevice:
    """
    Represents a Bluetooth device discovered by the application.

    This class contains identity/state information only.
    Actual BlueZ operations will be implemented separately.
    """

    address: str
    name: str = "Unknown"
    rssi: int | None = None

    connected: bool = False
    paired: bool = False

    def __str__(self) -> str:
        return f"{self.name} ({self.address})"

