import re
from app.security.base import BaseScanner, SecurityResult

class PIIScanner(BaseScanner):
    def __init__(self):
        self.patterns = {
            "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "CREDIT_CARD": r"\d{4}.\d{4}.\d{4}.\d{4}",
            "TCKN": r"\b[1-9]\d{10}\b",
            "PHONE_TR": r"(?:\+90|0)?5\d{2}[-.\s]?\d{3}[-.\s]?\d{4}"
        }
    async def scan(self, text: str) -> SecurityResult:
        processed_text = text
        found_pii = []

        for label, pattern in self.patterns.items():
            if re.search(pattern, processed_text):
                found_pii.append(label)
                processed_text = re.sub(pattern, f"[{label} REDACTED]", processed_text)
        return SecurityResult(
            allowed = True,
            message = f"PII Detected & Masked: {', '.join(found_pii)}" if found_pii else "Clean",
            sanitized_text = processed_text
        )