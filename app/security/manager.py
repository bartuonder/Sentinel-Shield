from typing import List, Dict, Any
from app.security.base import BaseScanner, SecurityResult, ScanStatus
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

    async def run(self, text: str) -> Dict[str, Any]:
        current_text = text
        trace_logs = []
        final_status = ScanStatus.ALLOWED
        block_reason = None

        for scanner in self.scanners:

            result: SecurityResult = await scanner.scan(current_text)

            trace_logs.append({
                "scanner": result.scanner_name,
                "status": result.status,
                "message": result.message,
                "metadata": result.metadata
            })

            current_text = result.sanitized_text

            if result.status != ScanStatus.ALLOWED:
                final_status = result.status
                block_reason = f"[{result.scanner_name}] {result.message}"
                break

        return {
            "allowed": final_status == ScanStatus.ALLOWED,
            "status": final_status,
            "final_text": current_text,
            "block_reason": block_reason,
            "trace": trace_logs
        }