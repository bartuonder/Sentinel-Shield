import re
from app.security.base import BaseScanner, SecurityResult, ScanStatus

class PIIScanner(BaseScanner):
    def __init__(self):

        self.patterns = {
            "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",

            "PHONE_TR": r"(?:\+90|0)?5\d{2}[-.\s]?\d{3}(?:[-.\s]?\d{4}|[-.\s]?\d{2}[-.\s]?\d{2})",

            "CREDIT_CARD_CANDIDATE": r"\b(?:\d[ -]*?){13,16}\b",

            "TCKN_CANDIDATE": r"\b[1-9]\d{10}\b"
        }

    def _verify_luhn(self, cc_number: str) -> bool:

        digits = [int(d) for d in cc_number if d.isdigit()]
        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    def _verify_tckn(self, tckn: str) -> bool:

        if len(tckn) != 11 or tckn.startswith('0'): return False

        try:
            digits = [int(d) for d in tckn]
        except ValueError:
            return False
        d = digits

        c1 = (sum(d[0:10:2]) * 7 - sum(d[1:9:2])) % 10

        c2 = sum(d[:10]) % 10

        return c1 == d[9] and c2 == d[10]

    async def scan(self, text: str) -> SecurityResult:
        processed_text = text
        found_pii = []

        if re.search(self.patterns["EMAIL"], processed_text):
            processed_text = re.sub(self.patterns["EMAIL"], "[EMAIL REDACTED]", processed_text)
            found_pii.append("EMAIL")

        phone_matches = list(re.finditer(self.patterns["PHONE_TR"], processed_text))
        if phone_matches:
            found_pii.append("PHONE")
            for match in phone_matches:

                processed_text = processed_text.replace(match.group(), "[PHONE REDACTED]")

        for match in re.finditer(self.patterns["CREDIT_CARD_CANDIDATE"], text):
            candidate = match.group()
            clean_num = re.sub(r"\D", "", candidate)
            if len(clean_num) > 12 and self._verify_luhn(clean_num):
                found_pii.append("CREDIT_CARD")
                processed_text = processed_text.replace(candidate, "[CREDIT_CARD REDACTED]")

        for match in re.finditer(self.patterns["TCKN_CANDIDATE"], text):
            candidate = match.group()
            if self._verify_tckn(candidate):
                found_pii.append("TCKN")
                processed_text = processed_text.replace(candidate, "[TCKN REDACTED]")

        return SecurityResult(
            status=ScanStatus.ALLOWED,
            scanner_name="PIIScanner",
            message=f"PII Masked: {', '.join(set(found_pii))}" if found_pii else "Clean",
            sanitized_text=processed_text,
            metadata={"found_types": list(set(found_pii))}
        )