from dataclasses import dataclass


@dataclass(frozen=True)
class FastPairMetadata:
    """
    Metadata associated with a Fast Pair Model ID.

    Only fields that our application has actually obtained from a
    legitimate metadata source should be populated.
    """

    model_id: int
    name: str | None = None
    company_name: str | None = None
    image_url: str | None = None
    device_type: str | None = None
    features: tuple[int | str, ...] = ()
    anti_spoofing_public_key: bytes | None = None

class MetadataProvider:
    """
    Interface for obtaining Fast Pair metadata.

    Implementations can later use an officially authorized source,
    a local manufacturer-provided database, or another permitted
    backend.
    """

    async def get(self, model_id: int) -> FastPairMetadata | None:
        raise NotImplementedError
