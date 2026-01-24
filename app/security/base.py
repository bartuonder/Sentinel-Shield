from abc import ABC, abstractmethod

class SecurityResult:
    def __init__(self, allowed: bool, message: str, sanitized_text: str):
        self.allowed = allowed
        self.message = message
        self.sanitized_text = sanitized_text

class BaseScanner(ABC):

    @abstractmethod
    async def scan(self, text: str) -> SecurityResult:
        pass