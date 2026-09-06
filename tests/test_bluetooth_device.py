from fastpair_mic.bluetooth.device import BluetoothDevice


def test_bluetooth_device():
    device = BluetoothDevice(
        address="AA:BB:CC:DD:EE:FF",
        name="Test Earbuds",
        rssi=-50,
    )

    assert device.address == "AA:BB:CC:DD:EE:FF"
    assert device.name == "Test Earbuds"
    assert device.rssi == -50
    assert device.connected is False
    assert device.paired is False

