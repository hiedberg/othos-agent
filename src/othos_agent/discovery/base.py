from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class DiscoveryStrategy(ABC):

    @abstractmethod
    async def discover(self, subnet: str, hints: Optional[list] = None) -> list[dict]:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...
