from dataclasses import dataclass


@dataclass
class FastPairModel:
    model_id: int
    name: str
    display_name: str
    company_name: str
    device_type: str
    public_key: bytes | None
    image_url: str | None


class NearbyDevicesClient:
    """
    Interface for retrieving Fast Pair model metadata.

    The actual transport/authentication implementation will be
    added separately.
    """

    async def get_model(self, model_id: int) -> FastPairModel | None:
        raise NotImplementedError
