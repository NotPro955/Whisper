from fastpair_mic.fastpair.gatt import (
    GattCharacteristicInfo,
    GattServiceInfo,
)


def test_gatt_characteristic_info():
    characteristic = GattCharacteristicInfo(
        uuid="1234",
        properties=("read", "notify"),
    )

    assert characteristic.uuid == "1234"
    assert "read" in characteristic.properties
    assert "notify" in characteristic.properties


def test_gatt_service_info():
    characteristic = GattCharacteristicInfo(
        uuid="1234",
        properties=("read",),
    )

    service = GattServiceInfo(
        uuid="5678",
        characteristics=(characteristic,),
    )

    assert service.uuid == "5678"
    assert len(service.characteristics) == 1
