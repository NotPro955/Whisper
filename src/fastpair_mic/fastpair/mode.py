from dataclasses import dataclass


@dataclass(frozen=True)
class EarbudMode:
    """
    Best-effort mode classification based on observable BLE state.

    This is intentionally conservative. BLE advertising alone cannot
    universally prove that an earbud is in Classic Bluetooth pairing mode.
    """

    advertising: bool
    connectable: bool
    fast_pair_advertising: bool
    description: str


def classify_mode(
    *,
    advertising: bool,
    connectable: bool,
    fast_pair_advertising: bool,
) -> EarbudMode:
    if not advertising:
        description = "not advertising / state unknown"
    elif fast_pair_advertising and connectable:
        description = "Fast Pair advertising / likely discoverable"
    elif connectable:
        description = "BLE connectable / pairing state unknown"
    else:
        description = "BLE advertising but not known to be connectable"

    return EarbudMode(
        advertising=advertising,
        connectable=connectable,
        fast_pair_advertising=fast_pair_advertising,
        description=description,
    )
