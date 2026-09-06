import json
from pathlib import Path

from .metadata import FastPairMetadata, MetadataProvider


class LocalMetadataProvider(MetadataProvider):
    """
    Reads Fast Pair metadata from a local JSON file.

    This provider does not contain or generate anti-spoofing keys.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    async def get(self, model_id: int) -> FastPairMetadata | None:
        if not self.path.exists():
            return None

        data = json.loads(self.path.read_text())

        entry = data.get(f"{model_id:06X}")

        if entry is None:
            return None

        return FastPairMetadata(
            model_id=model_id,
            name=entry.get("name"),
            company_name=entry.get("company_name"),
            image_url=entry.get("image_url"),
            device_type=entry.get("device_type"),
            features=tuple(entry.get("features", [])),
        )
