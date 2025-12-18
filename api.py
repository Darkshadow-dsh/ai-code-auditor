from fastapi import FastAPI
from pydantic import BaseModel
from rules import find_hardcoded_secrets, find_eval_exec_usage
from rules import SEVERITY_SCORES
from web import app as flask_app
from starlette.middleware.wsgi import WSGIMiddleware



app = FastAPI(title="AI Code Auditor")
app.mount("/", WSGIMiddleware(flask_app))


class AnalyzeRequest(BaseModel):
    code: str

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    results = []
    results.extend(find_hardcoded_secrets(req.code))
    results.extend(find_eval_exec_usage(req.code))

    weights = {
        "LOW": 10,
        "MEDIUM": 25,
        "HIGH": 45
    }

    risk_score = 0
    for f in results:
        risk_score += weights.get(f.get("severity", "LOW"), 10)

    if risk_score > 100:
        risk_score = 100

    if risk_score >= 80:
        label = "CRITICAL"
    elif risk_score >= 50:
        label = "HIGH"
    elif risk_score >= 20:
        label = "MEDIUM"
    else:
        label = "LOW"

    return {
        "risk_score": risk_score,
        "risk_label": label,
        "total_findings": len(results),
        "findings": results
    }
