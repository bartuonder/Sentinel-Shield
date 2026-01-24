from typing import List
from app.security.base import BaseScanner, SecurityResult
from app.security.pii_scanner import PIIScanner
from app.security.injection_scanner import InjectionScanner
from app.security.llm_scanner import LLMGuardScanner


class SecurityPipeline:
    def __init__(self):

        self.scanners: List[BaseScanner] = [
            PIIScanner(),
            InjectionScanner(),
            LLMGuardScanner()
        ]

    async def run(self, text: str) -> dict:
        current_text = text
        trace_logs = []

        for scanner in self.scanners:

            result: SecurityResult = await scanner.scan(current_text)

            trace_logs.append({
                "scanner": scanner.__class__.__name__,
                "message": result.message,
                "allowed": result.allowed
            })

            current_text = result.sanitized_text

            if not result.allowed:
                return {
                    "final_allowed": False,
                    "final_text": current_text,
                    "block_reason": f"Blocked by {scanner.__class__.__name__}: {result.message}",
                    "trace": trace_logs
                }

        return {
            "final_allowed": True,
            "final_text": current_text,
            "block_reason": None,
            "trace": trace_logs
        }