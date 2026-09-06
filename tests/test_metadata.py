from fastpair_mic.fastpair.metadata import FastPairMetadata


def test_fast_pair_metadata():
    metadata = FastPairMetadata(
        model_id=0x705FEA,
        name="Test device",
        company_name="Test company",
    )

    assert metadata.model_id == 0x705FEA
    assert metadata.name == "Test device"
    assert metadata.company_name == "Test company"
    assert metadata.anti_spoofing_public_key is None
