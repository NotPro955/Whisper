from fastpair_mic.fastpair.mode import classify_mode


def test_fast_pair_discoverable():
    mode = classify_mode(
        advertising=True,
        connectable=True,
        fast_pair_advertising=True,
    )

    assert mode.fast_pair_advertising is True
    assert "Fast Pair" in mode.description


def test_non_advertising_state():
    mode = classify_mode(
        advertising=False,
        connectable=False,
        fast_pair_advertising=False,
    )

    assert mode.description == "not advertising / state unknown"
