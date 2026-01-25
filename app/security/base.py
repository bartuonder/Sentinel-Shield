from __future__ import annotations
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class ScanStatus(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    MONITOR = "MONITOR"

class SecurityResult(BaseModel):

    status: ScanStatus
    scanner_name: str
    message: str
    sanitized_text: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class BaseScanner(ABC):

    @abstractmethod
    async def scan(self, text: str) -> SecurityResult:
        pass