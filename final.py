import re

def find_hardcoded_secrets(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- DESEN KUTUPHANESI (MOBIL UYUMLU) ---
    patterns = {}

    # 1. BULUT SISTEMLERI (CLOUD)
    # ---------------------------
    # AWS Access Key
    aws_reg = (
        r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|"
        r"AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    )
    patterns["AWS Access Key"] = (aws_reg, "HIGH", "AWS giris anahtari.")

    # Google API Key
    patterns["Google API Key"] = (
        r"AIza[0-9A-Za-z\-_]{35}", 
        "HIGH", "Google API anahtari."
    )
    
    # Google OAuth
    patterns["Google OAuth"] = (
        r"ya29\.[0-9A-Za-z\-_]+", 
        "CRITICAL", "Google Oturum Tokeni!"
    )

    # Heroku API Key
    heroku_reg = (
        r"[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-"
        r"[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
    )
    patterns["Heroku Key"] = (heroku_reg, "HIGH", "Heroku anahtari.")

    # IBM Cloud IAM
    patterns["IBM Cloud"] = (
        r"bx:opa:256:[a
