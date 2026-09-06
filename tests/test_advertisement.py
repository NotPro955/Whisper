from fastpair_mic.fastpair.advertisement import (
    parse_fast_pair_service_data,
)


FAST_PAIR_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"


def test_realme_b_model_id():
    data = bytes.fromhex(
        "007058853415c68134115b"
    )

    result = parse_fast_pair_service_data(
        {
            FAST_PAIR_UUID: data,
        }
    )

    assert result is not None
    assert result.flags == 0x00
    assert result.model_id == 0x705885
    assert result.raw_data == data

