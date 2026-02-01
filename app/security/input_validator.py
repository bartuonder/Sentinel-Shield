import re
import unicodedata
from app.security.base import BaseScanner, SecurityResult, ScanStatus


class InputValidator(BaseScanner):
    def __init__(self):
        self.MAX_LEN = 4000

        self.REPEATED_CHAR_THRESHOLD = 0.8

        self.homoglyph_map = str.maketrans({
            'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
            'і': 'i', 'І': 'I', 'κ': 'k', 'Μ': 'M', 'ν': 'v', 'ο': 'o',
            '！': '!', '？': '?', '（': '(', '）': ')', '：': ':', '；': ';',
            '”': '"', '“': '"', '’': "'", '‘': "'"
        })

        self.blocklist_patterns = re.compile(
            r"(ignore previous instructions|system override|dan mode|jailbreak|"
            r"önceki talimatları unut|yeni bir rol yap|sistem mesajı)",
            re.IGNORECASE
        )

        self.invisible_chars = re.compile(r'[\u200b-\u200f\u202a-\u202e\ufeff]')

    def normalize_homoglyphs(self, text: str) -> str:

        normalized = unicodedata.normalize('NFKC', text)

        normalized = normalized.translate(self.homoglyph_map)
        return normalized

    def check_script_mixing(self, text: str) -> bool:

        words = text.split()
        for word in words:
            has_latin = bool(re.search(r'[a-zA-Z]', word))
            has_cyrillic = bool(re.search(r'[\u0400-\u04FF]', word))

            if has_latin and has_cyrillic:
                return True
        return False

    async def scan(self, text: str) -> SecurityResult:
        if not text or not text.strip():
            return SecurityResult(ScanStatus.BLOCKED, "InputValidator", "Empty input", text)

        if self.invisible_chars.search(text):

            text = self.invisible_chars.sub('', text)

        normalized = self.normalize_homoglyphs(text).lower()
        normalized = re.sub(r'\s+', ' ', normalized).strip()

        if self.check_script_mixing(text):
            return SecurityResult(ScanStatus.BLOCKED, "InputValidator", "Homograph Attack Detected (Script Mixing)",
                                  text)

        if self.blocklist_patterns.search(normalized):
            return SecurityResult(ScanStatus.BLOCKED, "InputValidator", "Basic Jailbreak Attempt", text)

        if len(normalized) > self.MAX_LEN:
            return SecurityResult(ScanStatus.BLOCKED, "InputValidator", "Input too long", normalized[:50])

        if len(normalized) > 50:
            unique_chars = len(set(normalized))
            ratio = unique_chars / len(normalized)
            if ratio < 0.05:
                return SecurityResult(ScanStatus.BLOCKED, "InputValidator", "Low entropy (Flood)", normalized[:50])

        word_count = len(normalized.split())
        if word_count > 0:
            avg_word_len = len(normalized) / word_count
            if avg_word_len > 25:
                return SecurityResult(ScanStatus.BLOCKED, "InputValidator", "Token flood", normalized[:50])

        return SecurityResult(ScanStatus.ALLOWED, "InputValidator", "Valid", normalized)