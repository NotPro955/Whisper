import json

import pytest

from fastpair_mic.fastpair.local_metadata import LocalMetadataProvider


@pytest.mark.asyncio
async def test_local_metadata_provider(tmp_path):
    database = tmp_path / "models.json"

    database.write_text(
        json.dumps(
            {
                "123456": {
                    "name": "Test Earbuds",
                    "company_name": "Test",
                    "device_type": "EARBUD",
                    "features": [1, 2],
                }
            }
        )
    )

    provider = LocalMetadataProvider(database)

    result = await provider.get(0x123456)

    assert result is not None
    assert result.model_id == 0x123456
    assert result.name == "Test Earbuds"
    assert result.company_name == "Test"
    assert result.features == (1, 2)


@pytest.mark.asyncio
async def test_unknown_model(tmp_path):
    database = tmp_path / "models.json"
    database.write_text("{}")

    provider = LocalMetadataProvider(database)

    result = await provider.get(0xABCDEF)

    assert result is None
