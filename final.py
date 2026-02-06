from flask import Flask, request, render_template_string
from rules import find_hardcoded_secrets, find_eval_exec_usage

app = Flask(__name__)

# --- PUANLAMA VE TÜRKÇELEŞTİRME MOTORU ---
def calculate_risk(code):
    results = []
    # Kuralları çalıştır
    results.extend(find_hardcoded_secrets(code))
    results.extend(find_eval_exec_usage(code))

    # Ağırlıklar
    weights = {"LOW": 10, "MEDIUM": 25, "HIGH": 45}
    risk_score = 0
    for f in results:
        risk_score += weights.get(f.get("severity", "LOW"), 10)

    # Skoru 100'e sabitle
    if risk_score > 100: risk_score = 100

    # İngilizce -> Türkçe Etiket Çevirisi
    if risk_score >= 80: label = "KRİTİK"
    elif risk_score >= 50: label = "YÜKSEK"
    elif risk_score >= 20: label = "ORTA"
    else: label = "DÜŞÜK"

    # Bulguları Türkçeleştirme (Basit map)
    for f in results:
        sev = f.get("severity", "LOW")
        if sev == "HIGH": f["severity_tr"] = "YÜKSEK"
        elif sev == "MEDIUM": f["severity_tr"] = "ORTA"
        elif sev == "LOW": f["severity_tr"] = "DÜŞÜK"
        else: f["severity_tr"] = sev

    return {
        "risk_score": risk_score,
        "risk_label": label,
        "total_findings": len(results),
        "findings": results
    }

# --- TASARIM (HTML/CSS) ---
TEMPLATE = """
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Güvenlik Tarayıcısı</title>
  <style>
    :root {
      --primary: #2563eb; /* Modern Mavi */
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text: #1e293b;
      --border: #e2e8f0;
      --critical: #dc2626;
      --high: #ea580c;
      --medium: #d97706;
      --low: #16a34a;
    }
    body {
      font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 20px;
      line-height: 1.5;
    }
    .container {
      max-width: 800px;
      margin: 40px auto;
      background: var(--card-bg);
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
      border: 1px solid var(--border);
    }
    h2 { margin-top: 0; font-weight: 700; color: #0f172a; letter-spacing: -0.5px; }
    p.desc { color: #64748b; margin-bottom: 25px; }
    
    textarea {
      width: 100%;
      height: 200px;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 14px;
      padding: 15px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background-color: #f8fafc;
      resize: vertical;
      box-sizing: border-box; /* Tașmayı engeller */
      outline: none;
      transition: border-color 0.2s;
    }
    textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1); }
    
    button {
      background-color: var(--primary);
      color: white;
      border: none;
      padding: 12px 24px;
      font-size: 16px;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      margin-top: 15px;
      transition: background-color 0.2s;
      width: 100%;
    }
    button:hover { background-color: #1d4ed8; }
    button:disabled { background-color: #94a3b8; cursor: not-allowed; }

    /* SONUÇ KARTLARI */
    .result-header {
      margin-top: 30px;
      padding: 20px;
      border-radius: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #f1f5f9;
    }
    .score-badge {
      font-size: 24px;
      font-weight: 800;
    }
    .label-badge {
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 14px;
      font-weight: 700;
      color: white;
      text-transform: uppercase;
    }
    
    /* RENK SINIFLARI */
    .KRİTİK { background-color: var(--critical); }
    .YÜKSEK { background-color: var(--high); }
    .ORTA { background-color: var(--medium); }
    .DÜŞÜK { background-color: var(--low); }
    
    .finding-card {
      border: 1px solid var(--border);
      border-left-width: 5px;
      border-radius: 6px;
      padding: 15px;
      margin-top: 15px;
      background: white;
    }
    .finding-card.YÜKSEK { border-left-color: var(--high); }
    .finding-card.ORTA { border-left-color: var(--medium); }
    .finding-card.DÜŞÜK { border-left-color: var(--low); }
    
    code {
      background: #e2e8f0;
      padding: 2px 5px;
      border-radius: 4px;
      font-family: monospace;
      color: #b91c1c;
    }
    .meta { font-size: 13px; color: #64748b; margin-bottom: 5px; font-weight: 600; }
    .fix-title { font-weight: 700; color: #334155; margin-right: 5px; }
  </style>
  <script>
    function showLoading() {
        const btn = document.getElementById('analyzeBtn');
        btn.innerHTML = 'Analiz Ediliyor...';
        btn.disabled = true;
        // Formu submit etmemiz lazım manuel olarak çünkü disable ettik
        document.forms[0].submit(); 
    }
  </script>
</head>
<body>
  <div class="container">
    <h2>AI Güvenlik Tarayıcısı</h2>
    <p class="desc">Python kodunuzu yapıştırın, güvenlik açıklarını ve gizli şifreleri saniyeler içinde tespit edelim.</p>

    <form method="post" onsubmit="showLoading()">
      <textarea name="code" placeholder="Kodunuzu buraya yapıştırın...">{{ code|e }}</textarea><br>
      <button type="submit" id="analyzeBtn">Analiz Et</button>
    </form>

    {% if result %}
      <div class="result-header">
        <div>
            <div style="font-size: 13px; color: #64748b; margin-bottom: 4px;">RİSK SKORU</div>
            <div class="score-badge" style="color: 
                {% if result.risk_score >= 80 %}#dc2626
                {% elif result.risk_score >= 50 %}#ea580c
                {% elif result.risk_score >= 20 %}#d97706
                {% else %}#16a34a{% endif %}">
                {{ result.risk_score }} / 100
            </div>
        </div>
        <div class="label-badge {{ result.risk_label }}">
            {{ result.risk_label }} SEVİYE
        </div>
      </div>

      <p style="margin-top: 20px; font-weight: 600; color: #334155;">
        Toplam {{ result.total_findings }} güvenlik açığı bulundu:
      </p>

      {% for f in result.findings %}
        <div class="finding-card {{ f.severity_tr }}">
          <div class="meta">{{ f.severity_tr }} RİSK — SATIR {{ f.line }}</div>
          <div style="margin-bottom: 8px; font-weight: 500;">{{ f.issue }}</div>
          <div style="background: #f1f5f9; padding: 10px; border-radius: 4px; overflow-x: auto; margin-bottom: 8px;">
            <code>{{ f.content }}</code>
          </div>
          <div style="font-size: 14px; color: #475569;">
            <span class="fix-title">Çözüm:</span> {{ f.recommendation }}
          </div>
        </div>
      {% endfor %}
    {% endif %}
  </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    code = ""
    result = None
    
    if request.method == "POST":
        code = request.form.get("code", "")
        if code:
            result = calculate_risk(code)

    return render_template_string(TEMPLATE, code=code, result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
