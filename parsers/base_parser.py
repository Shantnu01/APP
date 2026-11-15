"""
RepoGuard Base Parser Interface
"""

from abc import ABC, abstractmethod
from typing import List
from core.models import Dependency


class BaseParser(ABC):
    @abstractmethod
    def can_parse(self, filename: str) -> bool:
        """Determines if this parser handles the given manifest filename."""
        pass

    @abstractmethod
    def parse(self, content: bytes, filepath: str) -> List[Dependency]:
        """Extracts declared dependencies and versions from the manifest bytes."""
        pass
