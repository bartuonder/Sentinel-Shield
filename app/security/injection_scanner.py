import re
from app.security.base import BaseScanner, SecurityResult, ScanStatus


class InjectionScanner(BaseScanner):
    def __init__(self):
        self.sql_pattern = re.compile(
            r"(?:\b(UNION\s+ALL\s+SELECT|UNION\s+SELECT|INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE|ALTER\s+TABLE)\b)|(?:--|\/\*|\*\/|@@version)",
            re.IGNORECASE | re.DOTALL
        )

        self.cmd_pattern = re.compile(
            r"(;|\||&|\$|\`)\s*(ls|cat|rm|mkdir|nc|netcat|wget|curl|ping|clear|whoami)\b",
            re.IGNORECASE
        )

        self.xss_pattern = re.compile(
            r"(<script.*?>)|(javascript:)|(onerror\s*=)|(onload\s*=)|(eval\()|(document\.cookie)|(alert\()",
            re.IGNORECASE | re.DOTALL
        )

        self.jailbreak_pattern = re.compile(
            r"(?i)\b(ignore previous instructions|forget all instructions|act as DAN)\b",
            re.IGNORECASE
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

        if self.cmd_pattern.search(text):
            return SecurityResult(
                status=ScanStatus.BLOCKED,
                scanner_name="InjectionScanner",
                message="Potential Command Injection Detected",
                sanitized_text=text,
                metadata={"type": "CMDi"}
            )

        if self.xss_pattern.search(text):
            return SecurityResult(
                status=ScanStatus.BLOCKED,
                scanner_name="InjectionScanner",
                message="Potential XSS/Script Injection Detected",
                sanitized_text=text,
                metadata={"type": "XSS"}
            )

        if self.jailbreak_pattern.search(text):
            return SecurityResult(
                status=ScanStatus.BLOCKED,
                scanner_name="InjectionScanner",
                message="Basic Jailbreak Attempt Detected",
                sanitized_text=text,
                metadata={"type": "Jailbreak"}
            )

        return SecurityResult(
            status=ScanStatus.ALLOWED,
            scanner_name="InjectionScanner",
            message="No static injection patterns found",
            sanitized_text=text
        )