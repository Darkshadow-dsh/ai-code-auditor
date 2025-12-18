from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

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

  {% if error %}
    <div class="card HIGH">
      <b>Hata:</b> {{ error }}
    </div>
  {% endif %}

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

API_URL = "http://127.0.0.1:8000/analyze"

@app.route("/", methods=["GET", "POST"])
def index():
    code = ""
    result = None
    error = None

    if request.method == "POST":
        code = request.form.get("code", "")
        try:
            r = requests.post(API_URL, json={"code": code}, timeout=10)
            r.raise_for_status()
            result = r.json()
        except Exception as e:
            error = f"API'ye bağlanamadım. Uvicorn açık mı? Detay: {e}"

    return render_template_string(TEMPLATE, code=code, result=result, error=error)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
