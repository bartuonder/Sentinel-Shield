import logging
from app.security.base import BaseScanner, SecurityResult, ScanStatus
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

class PIIScanner(BaseScanner):
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()

        self.entities_to_detect = [
            "PHONE_NUMBER",
            "EMAIL_ADDRESS",
            "CREDIT_CARD",
            "CRYPTO",
            "IP_ADDRESS",
            "US_SSN",
            "PERSON",
            "LOCATION"
        ]

    async def scan(self, text: str) -> SecurityResult:
        try:

            results = self.analyzer.analyze(
                text=text,
                entities=self.entities_to_detect,
                language='en'
            )

            found_types = list(set([res.entity_type for res in results]))

            if not results:
                return SecurityResult(
                    status=ScanStatus.ALLOWED,
                    scanner_name="PIIScanner (Presidio AI)",
                    message="No PII detected",
                    sanitized_text=text
                )

            anonymized_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=results,
                operators={
                    "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
                    "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[PHONE HIDDEN]"}),
                    "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[CC HIDDEN]"})
                }
            )

            return SecurityResult(
                status=ScanStatus.ALLOWED,
                scanner_name="PIIScanner (Presidio AI)",
                message=f"PII Detected & Masked: {', '.join(found_types)}",
                sanitized_text=anonymized_result.text,
                metadata={"found_entities": found_types}
            )

        except Exception as e:
            print(f"Presidio Error: {e}")

            return SecurityResult(
                status=ScanStatus.ERROR,
                scanner_name="PIIScanner",
                message="PII Scan Error",
                sanitized_text=text
            )