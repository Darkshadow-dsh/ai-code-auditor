import re

def find_hardcoded_secrets(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- DESEN KUTUPHANESI (MOBIL UYUMLU) ---
    patterns = {}

    # 1. BULUT & ALTYAPI (CLOUD)
    # --------------------------
    # AWS Access Key
    aws_reg = (
        r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|"
        r"AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    )
    patterns["AWS Key"] = (aws_reg, "HIGH", "AWS Anahtari.")

    # Google API Key
    patterns["Google Key"] = (
        r"AIza[0-9A-Za-z\-_]{35}", 
        "HIGH", "Google API Key."
    )
    
    # Google OAuth
    patterns["Google OAuth"] = (
        r"ya29\.[0-9A-Za-z\-_]+", 
        "CRITICAL", "Google OAuth Token!"
    )

    # Azure (Shared Access Signature)
    azure_reg = (
        r"sig=[a-zA-Z0-9%]+\&se="
    )
    patterns["Azure SAS"] = (azure_reg, "HIGH", "Azure SAS Token.")

    # Heroku API Key
    heroku_reg = (
        r"[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-"
        r"[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
    )
    patterns["Heroku Key"] = (heroku_reg, "HIGH", "Heroku Anahtari.")

    # 2. FINANS & ODEME (FINTECH)
    # ---------------------------
    # Stripe (Canli)
    patterns["Stripe Secret"] = (
        r"sk_live_[0-9a-zA-Z]{24}", 
        "CRITICAL", "Stripe CANLI Anahtar!"
    )

    # PayPal Token
    patterns["PayPal Token"] = (
        r"access_token\$production\$[0-9a-z]{16}", 
        "CRITICAL", "PayPal Uretim Tokeni!"
    )

    # 3. KOD DEPOLARI & CI/CD
    # -----------------------
    # GitHub Token
    patterns["GitHub Token"] = (
        r"ghp_[0-9a-zA-Z]{36}", 
        "CRITICAL", "GitHub Token."
    )

    # Bitbucket / Atlassian
    patterns["Bitbucket"] = (
        r"xox[baprs]-([0-9a-zA-Z]{10,48})", 
        "HIGH", "Atlassian Token."
    )

    # 4. SOSYAL MEDYA
    # ---------------
    # Slack Bot
    patterns["Slack Bot"] = (
        r"xoxb-[0-9]{10,12}", 
        "HIGH", "Slack Bot Token."
    )
    
    # Slack Webhook
    patterns["Slack Webhook"] = (
        r"https://hooks\.slack\.com/services/T",
        "CRITICAL", "Slack Webhook URL."
    )

    # Discord Webhook
    discord_reg = (
        r"https://discord\.com/api/webhooks/"
        r"[0-9]{18,19}/[a-zA-Z0-9_-]+"
    )
    patterns["Discord Webhook"] = (
        discord_reg, "HIGH", "Discord Webhook."
    )

    # Telegram Bot
    tele_reg = (r"[0-9]{9,10}:[a-zA-Z0-9_-]{35}")
    patterns["Telegram Bot"] = (tele_reg, "HIGH", "Telegram Bot Token.")

    # Facebook & Twitter
    patterns["Facebook"] = (
        r"EAACEdEose0cBA[0-9A-Za-z]+", 
        "HIGH", "Facebook Token."
    )
    patterns["Twitter"] = (
        r"AAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]+", 
        "HIGH", "Twitter Token."
    )

    # 5. GENEL GUVENLIK RISKLERI
    # --------------------------
    # Generic Bearer Token (Authorization)
    bearer_reg = (r"Bearer [a-zA-Z0-9_\-\.]{20,}")
    patterns["Bearer Token"] = (
        bearer_reg, "MEDIUM", "Bearer Yetki Tokeni."
    )

    # Password in URL (http://user:pass@host)
    url_auth_reg = (
        r"https?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]"
    )
    patterns["URL Auth"] = (
        url_auth_reg, "CRITICAL", "URL icinde sifre var!"
    )

    # Database URL
    db_reg = (
        r"(postgres|mysql|redis|mongodb)://"
        r"[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@"
    )
    patterns["DB Link"] = (db_reg, "CRITICAL", "Veritabani Baglantisi.")

    # Private Key
    key_reg = (
        r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----"
    )
    patterns["Private Key"] = (key_reg, "CRITICAL", "Private Key acikta!")

    # Email & IP
    ip_reg = (
        r"\b(?!127\.0\.0\.1)(?!0\.0\.0\.0)"
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    patterns["IP Adresi"] = (ip_reg, "LOW", "Sunucu IP.")

    mail_reg = (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    )
    patterns["Email"] = (mail_reg, "LOW", "Email adresi.")


    # --- BASIT KONTROLLER ---
    crypto_weak = [
        ("hashlib.md5", "MEDIUM", "MD5 kirildi."),
        ("hashlib.sha1", "MEDIUM", "SHA1 guvensiz."),
        ("DES.new", "HIGH", "DES cok eski."),
        ("RC4", "HIGH", "RC4 guvensiz.")
    ]

    bad_configs = [
        ("debug=True", "HIGH", "Debug Modu Acik!"),
        ("DEBUG = True", "HIGH", "Debug Modu Acik!"),
        ("verify=False", "HIGH", "SSL Kontrolu Kapali!"),
        ("chmod 777", "HIGH", "Tum izinler acik (777).")
    ]

    keywords = ["password", "secret", "api_key", "access_token"]


    # --- TARAMA MOTORU ---
    for i, line in enumerate(lines):
        num = i + 1
        txt = line.strip()
        
        if not txt or txt.startswith("#"): continue

        # A) Regex Taramasi
        for name, data in patterns.items():
            if re.search(data[0], txt):
                findings.append({
                    "line": num,
                    "content": txt[:60],
                    "issue": name,
                    "severity": data[1],
                    "recommendation": data[2]
                })

        # B) Konfig & Kripto
        for check, sev, msg in (crypto_weak + bad_configs):
            if check in txt:
                findings.append({
                    "line": num,
                    "content": txt[:60],
                    "issue": "Guvenlik Zafiyeti",
                    "severity": sev,
                    "recommendation": msg
                })

        # C) Keyword Taramasi
        for kw in keywords:
            kw_reg = fr"{kw}\s*=\s*['\"].+['\"]"
            if re.search(kw_reg, txt, re.IGNORECASE):
                if "os.getenv" in txt or "environ" in txt: continue
                findings.append({
                    "line": num,
                    "content": txt[:60],
                    "issue": "Sabit Sifre",
                    "severity": "HIGH",
                    "recommendation": ".env kullanin."
                })

    return findings

def find_eval_exec_usage(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # TEHLIKELI FONKSIYONLAR
    funcs = {
        "eval(": "CRITICAL",
        "exec(": "CRITICAL",
        "pickle.loads(": "HIGH",
        "yaml.load(": "HIGH",
        "os.popen(": "MEDIUM",
        "subprocess.call(..., shell=True": "HIGH",
        "shutil.rmtree(": "HIGH", # Dosya silme
        "os.remove(": "MEDIUM"    # Dosya silme
    }
    
    # DOSYA YAZMA OPERASYONLARI (Supheli)
    file_writes = [
        r"open\(.*['\"]w['\"]\)", # open(..., 'w')
        r"open\(.*['\"]wb['\"]\)", # open(..., 'wb')
        r"open\(.*['\"]a['\"]\)"   # open(..., 'a')
    ]

    sql_errors = [
        r"execute\(\s*f['\"].*SELECT",
        r"execute\(\s*['\"].*SELECT.*%.*%\s*\(",
        r"\.cursor\(\)\.execute\(.*\%s.*\%" 
    ]

    for i, line in enumerate(lines):
        num = i + 1
        txt = line.strip()
        if txt.startswith("#"): continue

        # Fonksiyonlar
        for f, sev in funcs.items():
            clean_f = f.split("(")[0]
            if clean_f in txt:
                findings.append({
                    "line": num,
                    "content": txt[:60],
                    "issue": "Tehlikeli Fonksiyon",
                    "severity": sev,
                    "recommendation": f"{clean_f} risklidir."
                })

        # Dosya Yazma
        for pat in file_writes:
            if re.search(pat, txt):
                findings.append({
                    "line": num,
                    "content": txt[:60],
                    "issue": "Dosya Yazma Islemi",
                    "severity": "MEDIUM",
                    "recommendation": "Kodun dosya yazmasi guvenli mi?"
                })

        # SQL
        for pat in sql_errors:
            if re.search(pat, txt, re.IGNORECASE):
                findings.append({
                    "line": num,
                    "content": txt[:60],
                    "issue": "SQL Injection",
                    "severity": "HIGH",
                    "recommendation": "Parametreli sorgu kullanin."
                })

    return findings
