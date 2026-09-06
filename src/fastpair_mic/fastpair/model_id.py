from .capabilities import MODEL_ID_UUID
from .gatt import GattClient


async def read_model_id_characteristic(
    client: GattClient,
) -> bytes:
    """
    Read the raw value exposed by the Fast Pair Model ID characteristic.

    We intentionally do not interpret the value here. The advertisement
    Model ID and the characteristic value are kept separate.
    """

    if not client.client or not client.client.is_connected:
        raise RuntimeError("BLE device is not connected")

    return bytes(
        await client.client.read_gatt_char(MODEL_ID_UUID)
    )

