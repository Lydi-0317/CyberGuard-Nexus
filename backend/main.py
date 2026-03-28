from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="CyberGuard Nexus API", version="1.0.0")

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "CyberGuard Nexus API - Ready for scam detection!"}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "scam-detection"}

class TextInput(BaseModel):
    text: str

@app.post("/detect/scam-text")
async def detect_scam_text(input_data: TextInput):
    text = input_data.text
    # Simple keyword + length detector (ML later)
    scam_keywords = ["OTP", "urgent", "bank account", "prize won", "click here"]
    score = sum(1 for word in scam_keywords if word.lower() in text.lower())
    length_score = min(len(text)/100, 1.0)  # Suspiciously long?
    
    risk = min((score + length_score) / 3, 1.0)
    
    return {
        "text": text,
        "risk_score": round(risk, 2),
        "risk_level": "HIGH" if risk > 0.7 else "MEDIUM" if risk > 0.4 else "LOW",
        "flags": [kw for kw in scam_keywords if kw.lower() in text.lower()]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)