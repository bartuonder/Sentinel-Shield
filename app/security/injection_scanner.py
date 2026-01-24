import re
from app.security.base import BaseScanner, SecurityResult

class InjectionScanner(BaseScanner):

    def __init__(self):
        self.patterns = {
            "SQL_INJECTION": r"(SELECT|DROP|DELETE|UPDATE|INSERT)\s+.*FROM",
            "SCRIPT_INJECTION": r"<script>|javascript:",
        }
    async def scan(self, text: str) -> SecurityResult:
        for label, pattern in self.patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                return SecurityResult(
                    allowed = False,
                    message = f"Attack Detected: {label}",
                    sanitized_text = text
                )
        return SecurityResult(allowed = True, message = "No static patterns found", sanitized_text = text)

