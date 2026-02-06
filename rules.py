import re

def find_hardcoded_secrets(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- 1. SEVİYE: VENDOR SPESİFİK API KEYLER ---
    vendor_patterns = {
        "Google API Key": (r"AIza[0-9A-Za-z\-_]{35}", "HIGH", "Google API anahtarı ifşa olmuş."),
        "AWS Access Key": (r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "HIGH", "AWS Access Key ifşa olmuş."),
        "GitHub Token": (r"ghp_[0-9a-zA-Z]{36}", "CRITICAL", "GitHub Personal Access Token ifşa olmuş."),
        "Stripe Secret": (r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL", "Stripe Ödeme Anahtarı (Canlı) ifşa olmuş!"),
        "Slack Token": (r"xox[baprs]-([0-9a-zA-Z]{10,48})", "HIGH", "Slack Bot Token ifşa olmuş."),
        "Heroku API Key": (r"[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "HIGH", "Heroku API Key ifşa olmuş."),
        "Facebook Token": (r"EAACEdEose0cBA[0-9A-Za-z]+", "HIGH", "Facebook Access Token ifşa olmuş."),
        "Twilio Auth": (r"SK[0-9a-fA-F]{32}", "HIGH", "Twilio API Anahtarı ifşa olmuş.")
    }

    # --- 2. SEVİYE: GENEL VERİ SIZINTILARI ---
    general_patterns = {
        # HATAYI ÖNLEMEK İÇİN BU SATIRI GÜVENLİ HALE GETİRDİK:
        "IPv4 Adresi": (
            r"\b(?!127\.0\.0\.1)(?!0\.0\.0\.0)"
            r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", 
            "LOW", 
            "Kod içinde sunucu IP adresi unutulmuş."
        ),
        "Email Adresi": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "LOW", "Kod içinde e-posta adresi (kişisel veri) var."),
        "Private Key": (r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----", "CRITICAL", "SSH/SSL Özel Anahtarı (Private Key) açıkta!")
    }

    # --- 3. SEVİYE: KRİPTOGRAFİK ZAYIFLIKLAR ---
    crypto_weaknesses = [
        ("hashlib.md5", "MEDIUM", "MD5 güvenli değildir (kırılabilir). SHA-256 kullanın."),
        ("hashlib.sha1", "MEDIUM", "SHA1 güvenli değildir. SHA-256 kullanın."),
        ("DES.new", "HIGH", "DES şifreleme
