import re
import logging
import base64
import binascii
import unicodedata
from app.security.base import BaseScanner, SecurityResult, ScanStatus
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine

logger = logging.getLogger("PIIScanner")


class PIIScanner(BaseScanner):
    def __init__(self):
        try:
            nlp_config = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": "en_core_web_sm"}])
            self.analyzer = AnalyzerEngine(nlp_engine=nlp_config)
            self.anonymizer = AnonymizerEngine()
            self.active = True

            self.word_map = {
                'sıfır': '0', 'bir': '1', 'iki': '2', 'üç': '3', 'dört': '4',
                'beş': '5', 'altı': '6', 'yedi': '7', 'sekiz': '8', 'dokuz': '9',
                'on': '1', 'yirmi': '2', 'otuz': '3', 'kırk': '4', 'elli': '5',
                'altmış': '6', 'yetmiş': '7', 'seksen': '8', 'doksan': '9',
                'yüz': '', 'bin': '', 'milyon': '', 'milyar': '',
                'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4', 'five': '5',
                'six': '6', 'seven': '7', 'eight': '8', 'nine': '9'
            }

            self.patterns = {
                "TR_TCKN": re.compile(r"\b[1-9]\d{10}\b"),
                "TR_PHONE": re.compile(r"(?:\+90|0)?\s*5\d{2}\s*\d{3}\s*\d{2}\s*\d{2}"),
                "TR_IBAN": re.compile(r"TR\d{2}\s?(\d{4}\s?){6}"),
                "CREDIT_CARD": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b")
            }

            self.invisible_chars = re.compile(r'[\u200b-\u200f\u202a-\u202e\ufeff\u2060-\u2064]')

        except Exception as e:
            logger.error(f"PII Init Error: {e}")
            self.active = False

    def verify_tckn(self, tckn: str) -> bool:
        if len(tckn) != 11 or tckn[0] == '0': return False
        try:
            d = [int(c) for c in tckn]
            d10 = ((sum(d[0:9:2]) * 7) - sum(d[1:8:2])) % 10
            d11 = sum(d[:10]) % 10
            return d[9] == d10 and d[10] == d11
        except:
            return False

    def clean_invisible_chars(self, text: str) -> str:
        return self.invisible_chars.sub('', text)

    def decode_and_scan(self, text: str) -> dict:
        detected_risks = []
        sanitized_text = text

        potential_payloads = re.findall(r'[A-Za-z0-9+/=]{10,}', text)

        for payload in potential_payloads:
            decoded_text = None
            try:
                missing_padding = len(payload) % 4
                padded_payload = payload + '=' * (4 - missing_padding) if missing_padding else payload
                decoded_bytes = base64.b64decode(padded_payload, validate=True)
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
            except:
                pass

            if not decoded_text:
                try:
                    decoded_bytes = binascii.unhexlify(payload)
                    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                except:
                    pass

            if decoded_text:
                digits = re.sub(r'\D', '', decoded_text)
                risk_found = False

                if len(digits) == 11 and self.verify_tckn(digits):
                    detected_risks.append("TR_TCKN_ENCODED")
                    risk_found = True
                elif len(digits) == 16:
                    detected_risks.append("CREDIT_CARD_ENCODED")
                    risk_found = True

                if risk_found:
                    sanitized_text = sanitized_text.replace(payload, "[ENCODED PII REDACTED]")

        return {"risks": list(set(detected_risks)), "sanitized_text": sanitized_text}

    def normalize_aggressive(self, text: str) -> str:
        text = unicodedata.normalize('NFKC', text).casefold()
        words = text.split()
        res = []
        for w in words:
            clean_w = re.sub(r'[^\w]', '', w)
            if clean_w in self.word_map:
                res.append(self.word_map[clean_w])
            else:
                res.append(w)
        intermediate = " ".join(res)
        return re.sub(r'[^0-9]', '', intermediate)

    def mask_pii_smart(self, text: str, matches: list) -> str:
        if not matches: return text
        matches.sort(key=lambda x: (x['start'], -(x['end'] - x['start'])))
        non_overlapping = []
        last_end = -1
        for m in matches:
            if m['start'] >= last_end:
                non_overlapping.append(m)
                last_end = m['end']
        non_overlapping.sort(key=lambda x: x['start'], reverse=True)
        chars = list(text)
        for m in non_overlapping:
            chars[m['start']:m['end']] = list(f"[{m['label']} REDACTED]")
        return "".join(chars)

    async def scan(self, text: str) -> SecurityResult:
        if not self.active:
            return SecurityResult(status=ScanStatus.MONITOR, scanner_name="PIIScanner", message="Service Down",
                                  sanitized_text=text)

        clean_text = self.clean_invisible_chars(text)

        encoded_result = self.decode_and_scan(clean_text)
        encoded_risks = encoded_result["risks"]

        current_text = encoded_result["sanitized_text"] if encoded_risks else clean_text

        detected_matches = []
        detected_labels = set()

        for label, pattern in self.patterns.items():
            for match in pattern.finditer(current_text):
                val = match.group()
                if label == "TR_TCKN" and not self.verify_tckn(val.replace(" ", "")): continue
                detected_matches.append({'start': match.start(), 'end': match.end(), 'label': label})
                detected_labels.add(label)

        try:
            results = self.analyzer.analyze(text=current_text, entities=["EMAIL_ADDRESS", "IP_ADDRESS"], language='en')
            for res in results:
                detected_matches.append({'start': res.start, 'end': res.end, 'label': "GLOBAL_PII"})
                detected_labels.add("GLOBAL_PII")
        except:
            pass

        sanitized_original = self.mask_pii_smart(current_text, detected_matches)

        hidden_found = False
        normalized_text = self.normalize_aggressive(current_text)
        for label, pattern in self.patterns.items():
            found_items = pattern.findall(normalized_text)
            for item in found_items:
                if label == "TR_TCKN" and not self.verify_tckn(item): continue
                if label not in detected_labels:
                    hidden_found = True
                    detected_labels.add(f"{label}_HIDDEN")
                    normalized_text = normalized_text.replace(item, f"[{label} REDACTED]")

        if encoded_risks:
            all_labels = list(set(encoded_risks + list(detected_labels)))
            return SecurityResult(
                status=ScanStatus.ALLOWED,
                scanner_name="PIIScanner",
                message=f"PII Detected (Included Encoded): {', '.join(all_labels)}",
                sanitized_text=sanitized_original,
                metadata={"hidden_pii": True, "detected_types": all_labels}
            )

        if hidden_found:
            return SecurityResult(
                status=ScanStatus.ALLOWED,
                scanner_name="PIIScanner",
                message=f"Hidden PII Detected: {', '.join(detected_labels)}",
                sanitized_text=normalized_text,
                metadata={"hidden_pii": True, "detected_types": list(detected_labels)}
            )

        if detected_labels:
            return SecurityResult(
                status=ScanStatus.ALLOWED,
                scanner_name="PIIScanner",
                message=f"PII Detected: {', '.join(detected_labels)}",
                sanitized_text=sanitized_original,
                metadata={"hidden_pii": False, "detected_types": list(detected_labels)}
            )

        return SecurityResult(status=ScanStatus.ALLOWED, scanner_name="PIIScanner", message="Clean",
                              sanitized_text=text)
