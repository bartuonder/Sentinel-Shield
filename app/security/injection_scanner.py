import re
from app.security.base import BaseScanner, SecurityResult, ScanStatus


class InjectionScanner(BaseScanner):
    def __init__(self):

        self.sql_pattern = re.compile(
            r"(?:\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE)\b.*\b(FROM|INTO|TABLE|DATABASE)\b)|(?:--|\/\*|\*\/|@@version)",
            re.IGNORECASE | re.DOTALL
        )

        # XSS: Yaygın payloadları yakala
        self.xss_pattern = re.compile(
            r"(<script.*?>)|(javascript:)|(onerror=)|(onload=)|(eval\()|(document\.cookie)",
            re.IGNORECASE | re.DOTALL
        )

    async def scan(self, text: str) -> SecurityResult:

        if self.sql_pattern.search(text):
            return SecurityResult(
                status=ScanStatus.BLOCKED,
                scanner_name="InjectionScanner",
                message="Potential SQL Injection Detected",
                sanitized_text=text,
                metadata={"type": "SQLi"}
            )

        if self.xss_pattern.search(text):
            return SecurityResult(
                status=ScanStatus.BLOCKED,
                scanner_name="InjectionScanner",
                message="Potential XSS/Script Injection Detected",
                sanitized_text=text,
                metadata={"type": "XSS"}
            )

        return SecurityResult(
            status=ScanStatus.ALLOWED,
            scanner_name="InjectionScanner",
            message="No static injection patterns found",
            sanitized_text=text
        )