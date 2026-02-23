# SHIELD 🛡️

**On-Device AI Fraud Detection for Indian UPI Users**

SHIELD is a voice-interactive AI assistant that helps Indian UPI users identify financial scams — in Hindi, Telugu, or English — before they lose money. It runs entirely on-device using AMD Ryzen AI hardware. No cloud. No data leaves your machine.

---

## The Problem

India's UPI ecosystem processes 185+ billion transactions annually. But with scale comes fraud:
- **13.42 lakh** fraud cases in FY24, losses exceeding **₹1,087 crore**
- **1 in 5** Indian families has experienced UPI fraud
- **51%** of victims never report — the real numbers are far worse
- Only **6%** of stolen funds are ever recovered

Current solutions detect fraud *after* the transaction. SHIELD detects it **before**.

## How It Works

1. User receives a suspicious SMS, call, or payment request
2. Opens SHIELD and asks: *"Yeh message safe hai kya?"*
3. System analyzes the message using local AI in under 5 seconds
4. Returns: risk score, fraud category, red flags, and plain-language explanation
5. All processing happens on-device — zero cloud, zero data leakage

## Architecture

```
Voice/Text/Screenshot
        │
   Input Processing (Whisper STT / EasyOCR)
        │
   Deterministic Tools (URL analysis, sender verification, urgency detection)
        │
   RAG Knowledge Base (100+ Indian scam patterns via LlamaIndex)
        │
   LLM Reasoning (Llama 3.2 3B via Ollama/Lemonade)
        │
   Risk Assessment + Voice Response
```

## Tech Stack

| Component | Tool | Purpose |
|-----------|------|---------|
| LLM | Llama 3.2 3B | Core reasoning engine |
| Speech-to-Text | Whisper | Hindi/English/Telugu transcription |
| Agent Framework | AMD GAIA | Agent orchestration + RAG |
| Model Serving | AMD Lemonade / Ollama | OpenAI-compatible local API |
| RAG | LlamaIndex | Knowledge base retrieval |
| OCR | EasyOCR | Screenshot text extraction |
| UI | Streamlit | Web interface |
| Network Monitor | psutil | Prove zero cloud connections |

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/shield.git
cd shield

# Setup
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt

# Install Ollama (https://ollama.com/download)
ollama pull llama3.2:3b

# Run
streamlit run app.py
```

## Fraud Categories Detected

1. **Phishing SMS** — Fake bank links (bit.ly/sbi-kyc)
2. **Digital Arrest** — Impersonating police/CBI over calls
3. **UPI Collect Fraud** — Fraudulent payment collect requests
4. **KYC Scams** — Fake "update your KYC" messages
5. **Investment Fraud** — Crypto/stock scam promises
6. **QR Code Scams** — Manipulated QR codes
7. **Fake Customer Care** — Spoofed helpline numbers
8. **Lottery Scams** — Prize/lottery winner fraud

## Track

**AMD Slingshot 2026** — AI + Cybersecurity & Privacy

## Team

Built by [Team Name] for AMD Slingshot 2026.

## License

MIT
