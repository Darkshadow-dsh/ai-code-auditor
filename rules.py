import re

def find_hardcoded_secrets(code_text):
    findings = []
    lines = code_text.split('\n')
    
    # --- PARCALANMIS REGEX (KOPYALAMA HATASINA SON) ---
    
    # 1. AWS KEY (Parca parca)
    aws_1 = r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|"
    aws_2 = r"AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    aws_pattern = aws_1 + aws_2

    # 2. GOOGLE KEY
    google_pattern = r"AIza[0-9A-Za-z\-_]{35}"
    
    # 3. STRIPE (ODEME)
    stripe_pattern = r"sk_live_[0-9a-zA-Z]{24}"

    # 4. GITHUB TOKEN
    github_pattern = r"ghp_[0-9a-zA-Z]{36}"

    # 5. IPV4 ADRESI (Cok uzun oldugu icin 3 parcaya bolduk)
    ip_1 = r"\b(?!127\.0\.0\.1)(?!0\.0\.0\.0)"
    ip_2 = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    ip_3 = r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ip_pattern = ip_1 + ip_2 + ip_3

    # 6. PRIVATE KEY
    pk_1 = r"-----BEGIN (RSA|DSA|EC|PGP) "
    pk_2 = r"PRIVATE KEY-----"
    pk_pattern = pk_1 + pk_2

    # DESENLERI LISTEYE EKLE
    patterns = {
        "AWS Key": (aws_pattern, "HIGH"),
        "Google Key": (google_pattern, "HIGH"),
        "Stripe Secret": (stripe_pattern, "CRITICAL"),
        "GitHub Token": (github_pattern, "CRITICAL"),
        "IP Adresi": (ip_pattern, "LOW"),
        "Private Key": (pk_pattern, "CRITICAL")
    }

    # --- BASIT KONTROLLER ---
    bad_configs = ["debug=True", "verify=False"]
    keywords = ["password", "secret", "api_key"]

    for i, line in enumerate(lines):
        num = i + 1
        txt = line.strip()
        if not txt or txt.startswith("#"): continue

        # A) REGEX TARAMASI
        for name, data in patterns.items():
            if re.search(data[0], txt):
                findings.append({
                    "line": num,
                    "content": txt[:50],
                    "issue": name,
                    "severity": data[1],
                    "recommendation": "Bunu gizleyin!"
                })

        # B) KELIME TARAMASI
        for kw in keywords:
            # kw="deger" formatini ara
            k_reg = fr"{kw}\s*=\s*['\"].+['\"]"
            if re.search(k_reg, txt, re.IGNORECASE):
                if "os.getenv" in txt: continue
                findings.append({
                    "line": num,
                    "content": txt[:50],
                    "issue": "Sabit Sifre",
                    "severity": "HIGH",
                    "recommendation": ".env kullanin"
                })

        # C) AYARLAR
        for bad in bad_configs:
            if bad in txt:
                findings.append({
                    "line": num,
                    "content": txt[:50],
                    "issue": "Riskli Ayar",
                    "severity": "HIGH",
                    "recommendation": "Bunu kapatin"
                })

    return findings

def find_eval_exec_usage(code_text):
    findings = []
    lines = code_text.split('\n')
    
    dangerous = ["eval(", "exec(", "pickle.loads("]
    
    for i, line in enumerate(lines):
        num = i + 1
        txt = line.strip()
        if txt.startswith("#"): continue

        for d in dangerous:
            if d in txt:
                findings.append({
                    "line": num,
                    "content": txt[:50],
                    "issue": "Tehlikeli Kod",
                    "severity": "CRITICAL",
                    "recommendation": f"{d} kullanmayin!"
                })
                
    return findings
