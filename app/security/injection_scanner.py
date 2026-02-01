import re
import urllib.parse
import unicodedata
import base64
import binascii
from app.security.base import BaseScanner, SecurityResult, ScanStatus


class InjectionScanner(BaseScanner):
    def __init__(self):

        self.hard_signatures = re.compile(
            r"(?:\b(exec\s+xp_|benchmark\(|sleep\(|load_file\()|"
            r"(\b(union\s+all\s+select|union\s+select|information_schema)\b)|"
            r"(\b(or|and)\s+[\d']+\s*=\s*[\d']+\b)|"
            r"(\b(or|and)\s+[\d']+\s*like\s*[\d']+\b)|"
            r"(;.*?\b(wget|curl|nc|netcat|whoami|reboot|chmod|cat /etc/passwd)\b))",
            re.IGNORECASE
        )

        self.manipulation_keywords = {

            "ignore": 0.3, "previous": 0.2, "instruction": 0.2, "limit": 0.2,
            "override": 0.5, "system": 0.2, "developer": 0.3, "mode": 0.2,

            "act as": 0.4, "simulate": 0.4, "roleplay": 0.4, "jailbreak": 0.6,
            "never": 0.2, "refuse": 0.2, "bypass": 0.5, "dan mode": 0.6,
            "hypothetical": 0.3, "fictional": 0.3, "character": 0.2,

            "unut": 0.3, "yoksay": 0.3, "önceki": 0.2, "talimat": 0.2,
            "sistem": 0.2, "kurallar": 0.2, "devre dışı": 0.4, "mod": 0.2,

            "davran": 0.3, "rol yap": 0.4, "sadece": 0.1, "motor": 0.1,
            "asla": 0.2, "yapay zeka": 0.1, "filtre": 0.3, "sanal": 0.2,
            "kurgusal": 0.3, "senaryo": 0.2, "karakter": 0.2
        }

        self.soft_sql_keywords = {
            "select": 0.1, "from": 0.1, "drop": 0.3, "table": 0.2,
            "insert": 0.2, "update": 0.2, "delete": 0.3, "where": 0.1,
            "having": 0.2, "like": 0.1, "--": 0.2, "#": 0.2, "version": 0.1
        }

        self.skeleton_keywords = ["unionselect", "insertinto", "droptable", "scriptalert", "xp_cmdshell", "or1=1",
                                  "or1like1"]
        self.leetspeak_map = str.maketrans(
            {'1': 'i', '0': 'o', '5': 's', '7': 't', '3': 'e', '4': 'a', '@': 'a', '$': 's'})

        self.invisible_chars = re.compile(r'[\u200b-\u200f\u202a-\u202e\ufeff\u2060-\u2064]')

    def clean_invisible_chars(self, text: str) -> str:
        return self.invisible_chars.sub('', text)

    def sanitize_payload(self, text: str) -> str:

        text = urllib.parse.unquote(text)

        text = self.clean_invisible_chars(text)

        text = unicodedata.normalize('NFKC', text).casefold()

        text_clean = re.sub(r'/\*.*?\*/', '', text)
        return text_clean

    def decode_and_check(self, text: str) -> list:

        detected_attacks = []
        potential_payloads = re.findall(r'[A-Za-z0-9+/=]{10,}', text)

        for payload in potential_payloads:
            decoded_text = None

            try:
                missing_padding = len(payload) % 4
                if missing_padding: payload += '=' * (4 - missing_padding)
                decoded_text = base64.b64decode(payload, validate=True).decode('utf-8', errors='ignore')
            except:
                pass

            if not decoded_text:
                try:
                    decoded_text = binascii.unhexlify(payload).decode('utf-8', errors='ignore')
                except:
                    pass

            if decoded_text:

                clean_decoded = self.sanitize_payload(decoded_text)
                if self.hard_signatures.search(clean_decoded):
                    detected_attacks.append("ENCODED_PAYLOAD_DETECTED")

        return list(set(detected_attacks))

    def get_skeleton(self, text: str) -> str:
        text = text.translate(self.leetspeak_map)
        return re.sub(r'[^a-z]', '', text)

    def calculate_heuristic_score(self, text: str) -> float:

        score = 0.0
        text_nospace = text.replace(" ", "")

        for kw, weight in self.manipulation_keywords.items():
            if kw in text or kw in text_nospace:
                score += weight

        for kw, weight in self.soft_sql_keywords.items():

            if kw in text:
                score += weight

        return score

    async def scan(self, text: str) -> SecurityResult:

        scan_text = self.sanitize_payload(text)
        risks = []

        encoded_attacks = self.decode_and_check(scan_text)
        if encoded_attacks:
            return SecurityResult(
                ScanStatus.BLOCKED,
                "InjectionScanner",
                "Critical Encoded Attack Detected",
                text,
                {"risk_score": 1.0, "type": "ENCODED_INJECTION"}
            )

        if self.hard_signatures.search(scan_text):
            return SecurityResult(
                ScanStatus.BLOCKED,
                "InjectionScanner",
                "Critical Attack Signature Detected",
                text,
                {"risk_score": 1.0, "type": "HARD_SIGNATURE"}
            )

        heuristic_score = self.calculate_heuristic_score(scan_text)
        if heuristic_score >= 0.8:
            risks.append("High_Likelihood_Attack")
            final_score = 0.9
        elif heuristic_score >= 0.5:
            risks.append("Suspicious_Intent")
            final_score = 0.6
        else:
            final_score = 0.0

        skeleton = self.get_skeleton(scan_text)
        for kw in self.skeleton_keywords:
            if kw in skeleton:
                if kw not in scan_text.replace(" ", ""):
                    risks.append(f"Obfuscated_{kw.upper()}")
                    final_score = 1.0
                    break

        if risks:
            status = ScanStatus.BLOCKED if final_score >= 0.8 else ScanStatus.MONITOR
            return SecurityResult(
                status,
                "InjectionScanner",
                f"Heuristic Risk: {', '.join(risks)}",
                text,
                {"risk_score": final_score, "flags": risks}
            )

        return SecurityResult(ScanStatus.ALLOWED, "InjectionScanner", "Clean", text)