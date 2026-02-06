from flask import Flask, request, render_template_string
# Senin rules.py dosyanı kullanıyoruz, API derdi bitti.
from rules import find_hardcoded_secrets, find_eval_exec_usage

app = Flask(__name__)

# --- HTML ŞABLONU (Senin tasarımın aynısı) ---
TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>AI Code Auditor</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 30px auto; }
    textarea { width: 100%; height: 260px; font-family: Consolas, monospace; }
    button { padding: 10px 16px; margin-top: 10px; cursor: pointer; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: 12px 14px; margin-top: 12px; }
    .HIGH { border-left: 6px solid #c0392b; }
    .MEDIUM { border-left: 6px solid #f39c12; }
    .LOW { border-left: 6px solid #27ae60; }
    .CRITICAL { border-left: 6px solid #8e44ad; }
    code { white-space: pre-wrap; }
  </style>
</head>
<body>
  <h2>AI Code Auditor (Mini Site)</h2>
  <p>Kodu yapıştır → Analyze.</p>

  <form method="post">
    <textarea name="code" placeholder="Paste code here...">{{ code|e }}</textarea><br>
    <button type="submit">Analyze</button>
  </form>

  {% if result %}
  <div class="card {{ result.risk_label }}">
    <b>Risk Score:</b> {{ result.risk_score }} / 100
    &nbsp; — &nbsp;
    <b>Label:</b> {{ result.risk_label }}
    <br>
    <b>Total findings:</b> {{ result.total_findings }}
   </div>

    {% for f in result.findings %}
      <div class="card {{ f.severity }}">
        <b>[{{ f.severity }}]</b> Line {{ f.line }} — {{ f.issue }}<br>
        <b>Code:</b> <code>{{ f.content }}</code><br>
        <b>Fix:</b> {{ f.recommendation }}
      </div>
    {% endfor %}
  {% endif %}
</body>
</html>
"""

# --- PUANLAMA MANTIĞI (Artık direkt burada çalışıyor) ---
def calculate_risk(code):
    results = []
    # rules.py dosyasından fonksiyonları çağırıyoruz
    results.extend(find_hardcoded_secrets(code))
    results.extend(find_eval_exec_usage(code))

    weights = {"LOW": 10, "MEDIUM": 25, "HIGH": 45}
    risk_score = 0
    for f in results:
        risk_score += weights.get(f.get("severity", "LOW"), 10)

    if risk_score > 100: risk_score = 100

    if risk_score >= 80: label = "CRITICAL"
    elif risk_score >= 50: label = "HIGH"
    elif risk_score >= 20: label = "MEDIUM"
    else: label = "LOW"

    return {
        "risk_score": risk_score,
        "risk_label": label,
        "total_findings": len(results),
        "findings": results
    }

@app.route("/", methods=["GET", "POST"])
def index():
    code = ""
    result = None
    
    if request.method == "POST":
        code = request.form.get("code", "")
        # API yok, internet yok, direkt işlem var!
        if code:
            result = calculate_risk(code)

    return render_template_string(TEMPLATE, code=code, result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
