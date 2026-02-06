from flask import Flask, render_template, request
# Senin yazdigin rules.py dosyasini cagiriyoruz
from rules import find_hardcoded_secrets, find_eval_exec_usage

# Iste Render'in aradigi "app" bu!
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    code_input = ""
    
    if request.method == 'POST':
        code_input = request.form.get('code_input', '')
        
        # Senin yazdigin guvenlik taramalarini calistir
        if code_input:
            secrets = find_hardcoded_secrets(code_input)
            risks = find_eval_exec_usage(code_input)
            results = secrets + risks

    return render_template('index.html', results=results, code_input=code_input)

if __name__ == "__main__":
    # Render icin gerekli port ayari
    app.run(host="0.0.0.0", port=10000)
