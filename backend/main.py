from fastapi import FastAPI
from pydantic import BaseModel
from transformers import pipeline
import uvicorn
import re
from typing import Optional, Dict, Any, List

app = FastAPI(title="🛡️ CyberGuard Nexus v1.0")

print("🔄 Loading BERT model...")
classifier = pipeline(
    "text-classification",
    model=r"C:\Users\Lydia\Projects\CyberGuard-Nexus\backend\ml-models\bert-scam-detector",
    local_files_only=True
)
print("✅ BERT loaded!")

# Live stats (mock)
STATS = {
    "blocked_today": 89,
    "total_scans": 1254,
    "accuracy": "F1: 0.957",
    "emergency": "1930 (Cyber Crime Helpline)"
}

class ScanInput(BaseModel):
    text: Optional[str] = None
    phone: Optional[str] = None
    url: Optional[str] = None
    medium: str = "unknown"

@app.post("/scan")
async def scan_threat(input: ScanInput) -> Dict[str, Any]:
    results = {"detections": {}, "risk_level": "LOW"}
    
    # Text BERT + patterns
    if input.text:
        bert = classifier(input.text)[0]
        is_spam = "SPAM" if "LABEL_1" in bert['label'] else "HAM"
        
        threats = []
        if re.search(r'http[s]?://|bit\.ly', input.text): threats.append("PHISHING_URL")
        if re.search(r'\b\d{4,6}\b.*OTP', input.text, re.I): threats.append("OTP_LEAK")
        if re.search(r'bank|upi|paytm|account', input.text, re.I): threats.append("BANK_FRAUD")
        
        results["detections"]["text"] = {
            "prediction": is_spam,
            "confidence": round(float(bert['score']), 3),
            "threats": threats
        }
    
    # Phone check
    if input.phone:
        results["detections"]["phone"] = {
            "is_fraud": bool(re.search(r'9[8-9]\d{8}', input.phone)),
            "risk": "HIGH"
        }
    
    # URL check
    if input.url:
        results["detections"]["url"] = {
            "is_phishing": bool(re.search(r'bit\.ly|tinyurl|short\.url', input.url)),
            "risk": "HIGH"
        }
    
    # Calculate overall risk
    total_threats = sum(len(d.get("threats", [])) for d in results["detections"].values())
    results["risk_level"] = "HIGH" if total_threats > 0 or any("HIGH" in str(v) for v in results["detections"].values()) else "LOW"
    results["medium"] = input.medium
    results["stats"] = STATS
    results["actions"] = ["Block immediately", "Never click links", "Report to 1930"]
    
    return results

@app.get("/")
async def root():
    return {"CyberGuard": "LIVE", "endpoint": "/scan", "docs": "/docs"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)