import re

def find_hardcoded_secrets(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- 1. SEVİYE: VENDOR SPESİFİK API KEYLER (Hassas Atış) ---
    # Bu desenler, firmaların kullandığı gerçek anahtar formatlarıdır.
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
        "IPv4 Adresi": (r"\b(?!127\.0\.0\.1)(?!0\.0\.0\.0)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2
