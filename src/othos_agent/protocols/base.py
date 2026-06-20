from abc import ABC, abstractmethod
from typing import Optional


class ScannerProtocol(ABC):

    @abstractmethod
    async def scan(
        self,
        ip: str,
        port: int,
        config: dict,
        scheme: str = "http",
        ws=None,
        request_id: Optional[str] = None,
        local_ip: str = "",
    ) -> dict:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...
