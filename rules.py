def find_hardcoded_secrets(code):
    findings = []

    keywords = ["api_key", "apikey", "secret", "token", "password"]

    for line_number, line in enumerate(code.split("\n"), start=1):
        lower_line = line.lower()
        for key in keywords:
            if key in lower_line and "=" in line and '"' in line:
                findings.append({
                    "line": line_number,
                    "issue": "Hard-coded secret",
                    "severity": "HIGH",
                    "content": line.strip(),
                    "recommendation": "Use environment variables instead of hard-coded secrets."
                })

    return findings
def find_eval_exec_usage(code):
    findings = []

    dangerous = ["eval(", "exec("]

    for line_number, line in enumerate(code.split("\n"), start=1):
        for d in dangerous:
            if d in line:
                findings.append({
                    "line": line_number,
                    "issue": "Use of eval/exec",
                    "severity": "HIGH",
                    "content": line.strip(),
                    "recommendation": "Avoid eval/exec. Use safe parsing or explicit logic instead."
                })

    return findings

SEVERITY_SCORES = {
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 50
}

