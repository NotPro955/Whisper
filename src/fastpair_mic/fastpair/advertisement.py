from dataclasses import dataclass


FAST_PAIR_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"


@dataclass
class FastPairAdvertisement:
    model_id: int
    flags: int
    raw_data: bytes


def parse_fast_pair_service_data(
    service_data: dict[str, bytes],
) -> FastPairAdvertisement | None:
    """
    Parse Fast Pair FE2C service data.

    Expected beginning of the packet:

        byte 0     flags
        byte 1-3   24-bit Model ID
    """

    for uuid, data in service_data.items():
        if uuid.lower() != FAST_PAIR_UUID:
            continue

        data = bytes(data)

        if len(data) < 4:
            return None

        flags = data[0]

        model_id = int.from_bytes(
            data[1:4],
            byteorder="big",
        )

        return FastPairAdvertisement(
            model_id=model_id,
            flags=flags,
            raw_data=data,
        )

    return None

