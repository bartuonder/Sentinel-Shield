from app.security.base import BaseScanner, SecurityResult, ScanStatus

class InputValidator(BaseScanner):
    async def scan(self, text: str) -> SecurityResult:
        if not text or not text.strip():
            return SecurityResult(
                status=ScanStatus.BLOCKED,
                message="Message cannot be empty.",
                scanner_name="InputValidator",
                sanitized_text=text
            )

        if len(text) > 2000:
            return SecurityResult(
                status=ScanStatus.BLOCKED,
                message="Message is too long. Max 2000 characters allowed.",
                scanner_name="InputValidator",
                sanitized_text=text[:2000]
            )

        if any(len(word) > 100 for word in text.split()):
             return SecurityResult(
                status=ScanStatus.BLOCKED,
                message="Invalid input format (Word too long).",
                scanner_name="InputValidator",
                sanitized_text=text
            )

        return SecurityResult(
            status=ScanStatus.ALLOWED,
            message="Input format valid",
            scanner_name="InputValidator",
            sanitized_text=text
        )