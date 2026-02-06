import re

def find_hardcoded_secrets(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- 1. SEVİYE: VENDOR SPESİFİK API KEYLER ---
    vendor_patterns = {
        "Google API Key": (
            r"AIza[0-9A-Za-z\-_]{35}", 
            "HIGH", 
            "Google API anahtarı ifşa olmuş."
        ),
        "AWS Access Key": (
            r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", 
            "HIGH", 
            "AWS Access Key ifşa olmuş."
        ),
        "GitHub Token": (
            r"ghp_[0-9a-zA-Z]{36}", 
            "CRITICAL", 
            "GitHub Personal Access Token ifşa olmuş."
        ),
        "Stripe Secret": (
            r"sk_live_[0-9a-zA-Z]{24}", 
            "CRITICAL", 
            "Stripe Ödeme Anahtarı (Canlı) ifşa olmuş!"
        ),
        "Slack Token": (
            r"xox[baprs]-([0-9a-zA-Z]{10,48})", 
            "HIGH", 
            "Slack Bot Token ifşa olmuş."
        ),
        "Heroku API Key": (
            r"[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", 
            "HIGH", 
            "Heroku API Key ifşa olmuş."
        ),
        "Facebook Token": (
            r"EAACEdEose0cBA[0-9A-Za-z]+", 
            "HIGH", 
            "Facebook Access Token ifşa olmuş."
        ),
        "Twilio Auth": (
            r"SK[0-9a-fA-F]{32}", 
            "HIGH", 
            "Twilio API Anahtarı ifşa olmuş."
        )
    }

    # --- 2. SEVİYE: GENEL VERİ SIZINTILARI ---
    # Not: Regex satırları kopyalama hatasını önlemek için bölündü
    general_patterns = {
        "IPv4 Adresi": (
            r"\b(?!127\.0\.0\.1)(?!0\.0\.0\.0)"
            r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", 
            "LOW", 
            "Kod içinde sunucu IP adresi unutulmuş."
        ),
        "Email Adresi": (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 
            "LOW", 
            "Kod içinde e-posta adresi (kişisel veri) var."
        ),
        "Private Key": (
            r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----", 
            "CRITICAL", 
            "SSH/SSL Özel Anahtarı (Private Key) açıkta!"
        )
    }

    # --- 3. SEVİYE: KRİPTOGRAFİK ZAYIFLIKLAR ---
    crypto_weaknesses = [
        ("hashlib.md5", "MEDIUM", "MD5 güvenli değildir. SHA-256 kullanın."),
        ("hashlib.sha1", "MEDIUM", "SHA1 güvenli değildir. SHA-256 kullanın."),
        ("DES.new", "HIGH", "DES şifreleme çok eskidir. AES kullanın.")
    ]

    # --- 4. SEVİYE: YANLIŞ KONFİGÜRASYON ---
    config_issues = [
        ("debug=True", "HIGH", "Üretim ortamında Debug modu açık bırakılmış."),
        ("DEBUG = True", "HIGH", "Üretim ortamında Debug modu açık bırakılmış."),
        ("verify=False", "HIGH", "SSL Sertifika kontrolü kapalı.")
    ]

    keyword_patterns = ["password", "passwd", "secret", "token", "api_key", "access_key", "jwt_secret"]

    for i, line in enumerate(lines):
        line_num = i + 1
        content = line.strip()
        if not content or content.startswith("#"): continue

        # A) Vendor Taraması
        for name, (pattern, severity, msg) in vendor_patterns.items():
            if re.search(pattern, content):
                findings.append({
                    "line": line_num, 
                    "content": content[:90], 
                    "issue": name, 
                    "severity": severity, 
                    "recommendation": msg
                })

        # B) Genel Sızıntı Taraması
        for name, (data, severity, msg) in general_patterns.items():
            if isinstance(data, tuple): pattern = data[0]
            else: pattern = data
            
            if re.search(pattern, content):
                findings.append({
                    "line": line_num, 
                    "content": content[:90], 
                    "issue": name, 
                    "severity": severity, 
                    "recommendation": msg
                })

        # C) Kripto & Konfigürasyon
        all_checks = crypto_weaknesses + config_issues
        for check_str, severity, msg in all_checks:
            if check_str in content:
                findings.append({
                    "line": line_num, 
                    "content": content[:90], 
                    "issue": "Güvenlik Zafiyeti", 
                    "severity": severity, 
                    "recommendation": msg
                })

        # D) Generic Keyword
        for kw in keyword_patterns:
            if re.search(fr"{kw}\s*=\s*['\"].+['\"]", content, re.IGNORECASE):
                if "os.getenv" in content or "os.environ" in content: continue
                findings.append({
                    "line": line_num, 
                    "content": content[:90], 
                    "issue": "Sabit Şifre Tespiti", 
                    "severity": "HIGH", 
                    "recommendation": f"'{kw}' için .env kullanın."
                })

    return findings

def find_eval_exec_usage(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- 5. SEVİYE: TEHLİKELİ FONKSİYONLAR ---
    dangerous_funcs = {
        "eval(": ("CRITICAL", "eval() kullanımı RCE açığı yaratır."),
        "exec(": ("CRITICAL", "exec() kullanımı RCE açığı yaratır."),
        "pickle.loads(": ("HIGH", "Güvensiz pickle verisi tehlikelidir."),
        "yaml.load(": ("HIGH", "yaml.safe_load kullanın."),
        "os.popen(": ("MEDIUM", "subprocess kullanın."),
        "tempfile.mktemp(": ("MEDIUM", "mktemp güvensizdir.")
    }

    # --- 6. SEVİYE: SQL INJECTION ---
    sql_patterns = [
        (r"execute\(\s*f['\"].*SELECT", "f-string ile SQL yazmayın."),
        (r"execute\(\s*['\"].*SELECT.*%.*%\s*\(", "String formatlama (%) kullanmayın."),
        (r"raw_sql\(\s*f['\"]", "raw_sql içinde f-string kullanmayın.")
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
                    "issue": "Tehlikeli Fonksiyon", 
                    "severity": sev, 
                    "recommendation": msg
                })

        for pattern, msg in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "line": line_num, 
                    "content": content[:8
