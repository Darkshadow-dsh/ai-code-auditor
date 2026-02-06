import re

def find_hardcoded_secrets(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- 1. SEVİYE: VENDOR SPESİFİK API KEYLER ---
    # Not: Telefondan kopyalarken bozulmasın diye hepsini parçaladık.
    vendor_patterns = {
        "Google API Key": (
            r"AIza[0-9A-Za-z\-_]{35}", 
            "HIGH", 
            "Google API anahtarı bulundu."
        ),
        "AWS Access Key": (
            r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)"
            r"[A-Z0-9]{16}", 
            "HIGH", 
            "AWS Access Key bulundu."
        ),
        "GitHub Token": (
            r"ghp_[0-9a-zA-Z]{36}", 
            "CRITICAL", 
            "GitHub Token bulundu."
        ),
        "Stripe Secret": (
            r"sk_live_[0-9a-zA-Z]{24}", 
            "CRITICAL", 
            "Stripe Canlı Anahtarı bulundu!"
        ),
        "Slack Token": (
            r"xox[baprs]-([0-9a-zA-Z]{10,48})", 
            "HIGH", 
            "Slack Bot Token bulundu."
        ),
        "Heroku API Key": (
            r"[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-"
            r"[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", 
            "HIGH", 
            "Heroku API Key bulundu."
        ),
        "Facebook Token": (
            r"EAACEdEose0cBA[0-9A-Za-z]+", 
            "HIGH", 
            "Facebook Token bulundu."
        ),
        "Twilio Auth": (
            r"SK[0-9a-fA-F]{32}", 
            "HIGH", 
            "Twilio Anahtarı bulundu."
        )
    }

    # --- 2. SEVİYE: GENEL VERİ SIZINTILARI ---
    general_patterns = {
        "IPv4 Adresi": (
            r"\b(?!127\.0\.0\.1)(?!0\.0\.0\.0)"
            r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", 
            "LOW", 
            "Sunucu IP adresi unutulmuş."
        ),
        "Email Adresi": (
            r"\b[A-Za-z0-9._%+-]+@"
            r"[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 
            "LOW", 
            "E-posta adresi bulundu."
        ),
        "Private Key": (
            r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----", 
            "CRITICAL", 
            "Özel Anahtar (Private Key) açıkta!"
        )
    }

    # --- 3. SEVİYE: KRİPTOGRAFİK ZAYIFLIKLAR ---
    crypto_weaknesses = [
        ("hashlib.md5", "MEDIUM", "MD5 kullanmayın."),
        ("hashlib.sha1", "MEDIUM", "SHA1 kullanmayın."),
        ("DES.new", "HIGH", "DES çok eskidir.")
    ]

    # --- 4. SEVİYE: KONFİGÜRASYON ---
    config_issues = [
        ("debug=True", "HIGH", "Debug modu açık."),
        ("DEBUG = True", "HIGH", "Debug modu açık."),
        ("verify=False", "HIGH", "SSL kontrolü kapalı.")
    ]

    keyword_patterns = ["password", "passwd", "secret", "token", "api_key"]

    for i, line in enumerate(lines):
        line_num = i + 1
        content = line.strip()
        if not content or content.startswith("#"): continue

        # A) Vendor Taraması
        for name, (pattern, severity, msg) in vendor_patterns.items():
            if re.search(pattern, content):
                findings.append({
                    "line": line_num, 
                    "content": content[:80], 
                    "issue": name, 
                    "severity": severity, 
                    "recommendation": msg
                })

        # B) Genel Taramalar
        for name, (data, severity, msg) in general_patterns.items():
            if isinstance(data, tuple): pattern = data[0]
            else: pattern = data
            
            if re.search(pattern, content):
                findings.append({
                    "line": line_num, 
                    "content": content[:80], 
                    "issue": name, 
                    "severity": severity, 
                    "recommendation": msg
                })

        # C) Basit Kontroller
        for check_str, severity, msg in (crypto_weaknesses + config_issues):
            if check_str in content:
                findings.append({
                    "line": line_num, 
                    "content": content[:80], 
                    "issue": "Güvenlik Riski", 
                    "severity": severity, 
                    "recommendation": msg
                })

        # D) Anahtar Kelimeler
        for kw in keyword_patterns:
            if re.search(fr"{kw}\s*=\s*['\"].+['\"]", content, re.IGNORECASE):
                if "os.getenv" in content: continue
                findings.append({
                    "line": line_num, 
                    "content": content[:80], 
                    "issue": "Sabit Şifre", 
                    "severity": "HIGH", 
                    "recommendation": f"'{kw}' için .env kullanın."
                })

    return findings

def find_eval_exec_usage(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- 5. SEVİYE: TEHLİKELİ FONKSİYONLAR ---
    dangerous_funcs = {
        "eval(": ("CRITICAL", "eval() RCE yaratır."),
        "exec(": ("CRITICAL", "exec() RCE yaratır."),
        "pickle.loads(": ("HIGH", "Pickle güvensizdir."),
        "yaml.load(": ("HIGH", "yaml.safe_load kullanın."),
        "os.popen(": ("MEDIUM", "subprocess kullanın.")
    }

    # --- 6. SEVİYE: SQL INJECTION ---
    sql_patterns = [
        (r"execute\(\s*f['\"].*SELECT", "f-string ile SQL yazmayın."),
        (r"execute\(\s*['\"].*SELECT.*%.*%\s*\(", "SQL'de % formatlama yapmayın.")
    ]

    for i, line in enumerate(lines):
        line_num = i + 1
        content = line.strip()
        if content.startswith("#"): continue

        for func, (sev, msg) in dangerous_funcs.items():
            if func in content:
                findings.append({
                    "line": line_num, 
                    "content": content[:80], 
                    "issue": "Tehlikeli Kod", 
                    "severity": sev, 
                    "recommendation": msg
                })

        for pattern, msg in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "line": line_num, 
                    "content": content[:80], 
                    "issue": "SQL Enjeksiyon Riski", 
                    "severity": "HIGH", 
                    "recommendation": msg
                })

    return findings
