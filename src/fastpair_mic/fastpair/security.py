from dataclasses import dataclass

from .capabilities import FastPairCapabilities


@dataclass(frozen=True)
class SecurityAssessment:
    """
    Non-destructive Fast Pair security assessment.

    This assessment only examines capabilities that have already
    been discovered through BLE/GATT inspection.

    It does not send crafted KBP packets or attempt to bypass
    authentication.
    """

    fast_pair_present: bool
    kbp_present: bool
    kbp_writable: bool
    kbp_notifiable: bool
    potentially_exposed: bool
    message: str


def assess_fast_pair_security(
    capabilities: FastPairCapabilities,
    *,
    kbp_writable: bool = False,
    kbp_notifiable: bool = False,
) -> SecurityAssessment:
    """
    Perform a capability-based, non-destructive assessment.

    A device exposing KBP does not automatically mean it is
    vulnerable. We therefore use conservative wording.
    """

    potentially_exposed = (
        capabilities.fast_pair
        and capabilities.key_based_pairing
        and kbp_writable
    )

    if not capabilities.fast_pair:
        message = (
            "Fast Pair service was not detected. "
            "This assessment cannot evaluate Fast Pair KBP exposure."
        )
    elif not capabilities.key_based_pairing:
        message = (
            "Fast Pair is present, but the KBP characteristic "
            "was not detected."
        )
    elif not kbp_writable:
        message = (
            "KBP characteristic is present but is not writable. "
            "No active security test was performed."
        )
    else:
        message = (
            "KBP capability is exposed. This indicates a potentially "
            "exposed Fast Pair security surface, but does not by itself "
            "prove that the device is vulnerable."
        )

    return SecurityAssessment(
        fast_pair_present=capabilities.fast_pair,
        kbp_present=capabilities.key_based_pairing,
        kbp_writable=kbp_writable,
        kbp_notifiable=kbp_notifiable,
        potentially_exposed=potentially_exposed,
        message=message,
    )
