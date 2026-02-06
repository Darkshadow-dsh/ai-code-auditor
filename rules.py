import re

def find_hardcoded_secrets(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- 1. GELİŞMİŞ REGEX DESENLERİ (Full Paket) ---
    patterns = {
        # --- BULUT & ALTYAPI ---
        "AWS Access Key": (r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "HIGH", "AWS Erişim Anahtarı tespit edildi."),
        "Google API Key": (r"AIza[0-9A-Za-z\-_]{35}", "HIGH", "Google API Key tespit edildi."),
        "Google OAuth": (r"ya29\.[0-9A-Za-z\-_]+", "CRITICAL", "Google OAuth Token (Oturum Anahtarı) ifşa olmuş!"),
        "Azure SAS Token": (r"sig=[a-zA-Z0-9%]+\&se=", "HIGH", "Azure Shared Access Signature bulundu."),
        "Heroku API Key": (r"[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "HIGH", "Heroku API Anahtarı tespit edildi."),
        "IBM Cloud Key": (r"bx:opa:256:[a-zA-Z0-9+/=]+", "HIGH", "IBM Cloud Anahtarı tespit edildi."),
        
        # --- FİNANS & ÖDEME ---
        "Stripe Secret": (r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL", "Stripe CANLI Ödeme Anahtarı! (Acil Değiştirin)"),
        "PayPal Token": (r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "CRITICAL", "PayPal Üretim Tokeni tespit edildi!"),
        
        # --- KOD & CI/CD ---
        "GitHub Token": (r"ghp_[0-9a-zA-Z]{36}", "CRITICAL", "GitHub Personal Access Token ifşa olmuş."),
        "Bitbucket Token": (r"xox[baprs]-([0-9a-zA-Z]{10,48})", "HIGH", "Atlassian/Bitbucket Token tespit edildi."),
        
        # --- SOSYAL MEDYA & MESAJLAŞMA ---
        "Slack Bot Token": (r"xoxb-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}", "HIGH", "Slack Bot Token tespit edildi."),
        "Slack Webhook": (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", "CRITICAL", "Slack Webhook URL (Mesaj sızdırabilir)."),
        "Discord Webhook": (r"https://discord\.com/api/webhooks/[0-9]{18,19}/[a-zA-Z0-9_-]+", "HIGH", "Discord Webhook URL tespit edildi."),
        "Telegram Bot": (r"[0-9]{9,10}:[a-zA-Z0-9_-]{35}", "HIGH", "Telegram Bot Token tespit edildi."),
        "Facebook Token": (r"EAACEdEose0cBA[0-9A-Za-z]+", "HIGH", "Facebook Access Token tespit edildi."),
        "Twitter Token": (r"AAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]+", "HIGH", "Twitter Bearer Token tespit edildi."),
        
        # --- ALTYAPI & GENEL ---
        "Database URL": (r"(postgres|mysql|redis|mongodb|amqp)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@", "CRITICAL", "Veritabanı bağlantı linki (Şifreli) tespit edildi!"),
        "Private Key": (r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----", "CRITICAL", "Private Key (Özel Kripto Anahtarı) açıkta!"),
        "JWT Token": (r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "MEDIUM", "JWT (JSON Web Token) oturum anahtarı olabilir."),
        "IPv4 Adresi": (r"\b(?!127\.0\.0\.1)(?!0\.0\.0\.0)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", "LOW", "Sunucu IP adresi kod içinde unutulmuş."),
        "Email Adresi": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "LOW", "E-posta adresi tespit edildi (Spam riski).")
    }

    # --- 2. BASİT KONTROLLER (Config & Kripto) ---
    simple_checks = [
        ("hashlib.md5", "MEDIUM", "MD5 algoritması güvensizdir (kırılabilir). SHA-256 kullanın."),
        ("hashlib.sha1", "MEDIUM", "SHA1 algoritması güvensizdir."),
        ("DES.new", "HIGH", "DES şifreleme çok eskidir. AES kullanın."),
        ("RC4", "HIGH", "RC4 algoritması güvensizdir."),
        ("debug=True", "HIGH", "Canlı ortamda Debug Modu açık bırakılmış!"),
        ("DEBUG = True", "HIGH", "Canlı ortamda Debug Modu açık bırakılmış!"),
        ("verify=False", "HIGH", "SSL Sertifika kontrolü devre dışı bırakılmış (Man-in-the-Middle riski)."),
        ("chmod 777", "HIGH", "Dosya izinleri herkese açık (777) ayarlanmış.")
    ]

    # --- 3. ANAHTAR KELİME TARAMASI (Heuristic) ---
    keywords = ["password", "secret", "api_key", "access_token", "auth_key", "client_secret"]

    for i, line in enumerate(lines):
        line_num = i + 1
        content = line.strip()
        
        if not content or content.startswith("#"): continue

        # A) Regex Taraması
        for name, (pattern, severity, msg) in patterns.items():
            if re.search(pattern, content):
                findings.append({
                    "line": line_num,
                    "content": content[:80],
                    "issue": name,
                    "severity": severity,
                    "recommendation": msg
                })

        # B) Basit Kontroller
        for check_str, severity, msg in simple_checks:
            if check_str in content:
                findings.append({
                    "line": line_num,
                    "content": content[:80],
                    "issue": "Güvenlik Zafiyeti",
                    "severity": severity,
                    "recommendation": msg
                })

        # C) Keyword Taraması (False Positive Korumalı)
        for kw in keywords:
            # kw = "deger" veya kw='deger' formatını arar
            kw_regex = fr"{kw}\s*=\s*['\"].+['\"]"
            if re.search(kw_regex, content, re.IGNORECASE):
                # Eğer satırda os.getenv veya environ varsa güvenli kabul et
                if "os.getenv" in content or "os.environ" in content:
                    continue
                    
                findings.append({
                    "line": line_num,
                    "content": content[:80],
                    "issue": "Sabit Şifre Şüphesi",
                    "severity": "HIGH",
                    "recommendation": f"'{kw}' değişkenini koda gömmeyin, Environment Variable (.env) kullanın."
                })

    return findings

def find_eval_exec_usage(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- TEHLİKELİ FONKSİYONLAR LİSTESİ ---
    dangerous_funcs = {
        "eval(": ("CRITICAL", "eval() kullanımı RCE (Uzaktan Kod Çalıştırma) açığı yaratır!"),
        "exec(": ("CRITICAL", "exec() kullanımı RCE açığı yaratır!"),
        "pickle.loads(": ("HIGH", "Güvenilmeyen veriyi pickle ile yüklemek kod çalıştırabilir."),
        "yaml.load(": ("HIGH", "yaml.load güvensizdir, yaml.safe_load kullanın."),
        "os.popen(": ("MEDIUM", "os.popen yerine subprocess modülünü güvenli parametrelerle kullanın."),
        "subprocess.call(..., shell=True": ("HIGH", "shell=True parametresi Komut Enjeksiyonuna yol açabilir."),
        "shutil.rmtree(": ("HIGH", "Kodun dosya/klasör silme yetkisi var, dikkatli olun."),
        "telnetlib.Telnet(": ("MEDIUM", "Telnet şifresizdir ve güvensizdir, SSH kullanın.")
    }
    
    # --- DOSYA YAZMA OPERASYONLARI ---
    file_writes = [
        (r"open\(.*['\"]w['\"]\)", "Kod dosya üzerine yazıyor (Write Mode)."),
        (r"open\(.*['\"]wb['\"]\)", "Kod binary dosya yazıyor."),
        (r"open\(.*['\"]a['\"]\)", "Kod dosyaya ekleme yapıyor (Append Mode).")
    ]

    # --- SQL INJECTION BELİRTİLERİ ---
    sql_patterns = [
        (r"execute\(\s*f['\"].*SELECT", "f-string ile SQL sorgusu oluşturulmuş (SQL Injection Riski)."),
        (r"execute\(\s*['\"].*SELECT.*%.*%\s*\(", "String formatlama (%) ile SQL sorgusu oluşturulmuş."),
        (r"\.cursor\(\)\.execute\(.*\%s.*\%", "Eski stil formatlama SQL Injection riski taşır.")
    ]

    for i, line in enumerate(lines):
        line_num = i + 1
        content = line.strip()
        
        if content.startswith("#"): continue

        # 1. Fonksiyon Taraması
        for func, (severity, msg) in dangerous_funcs.items():
            func_name = func.split("(")[0] # Sadece isme bak
            if func_name in content and "(" in content:
                findings.append({
                    "line": line_num,
                    "content": content[:80],
                    "issue": "Tehlikeli Fonksiyon",
                    "severity": severity,
                    "recommendation": msg
                })

        # 2. Dosya Yazma Taraması
        for pattern, msg in file_writes:
            if re.search(pattern, content):
                findings.append({
                    "line": line_num,
                    "content": content[:80],
                    "issue": "Dosya İşlemi",
                    "severity": "MEDIUM",
                    "recommendation": f"{msg} Yetkisiz değişiklik riskini kontrol edin."
                })

        # 3. SQL Injection Taraması
        for pattern, msg in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "line": line_num,
                    "content": content[:80],
                    "issue": "SQL Injection Riski",
                    "severity": "HIGH",
                    "recommendation": f"{msg} Parametreli sorgu (? veya :id) kullanın."
                })

    return findings
