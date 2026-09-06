from fastpair_mic.bluetooth.profiles import detect_from_uuids


A2DP = "0000110b-0000-1000-8000-00805f9b34fb"
HFP = "0000111e-0000-1000-8000-00805f9b34fb"
HSP = "00001108-0000-1000-8000-00805f9b34fb"


def test_a2dp_only():
    capabilities = detect_from_uuids([A2DP])

    assert capabilities.a2dp_sink is True
    assert capabilities.has_output is True
    assert capabilities.has_microphone is False


def test_hfp_microphone():
    capabilities = detect_from_uuids([HFP])

    assert capabilities.hfp is True
    assert capabilities.has_output is True
    assert capabilities.has_microphone is True


def test_multiple_profiles():
    capabilities = detect_from_uuids([A2DP, HFP])

    assert capabilities.a2dp_sink is True
    assert capabilities.hfp is True
    assert capabilities.has_output is True
    assert capabilities.has_microphone is True

