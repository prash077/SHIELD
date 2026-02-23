"""
SHIELD Configuration
====================
Every configurable value lives here. When switching from Ollama (development)
to Lemonade (AMD Ryzen AI), you only change values in this file.
"""

# ─── LLM Configuration ────────────────────────────────────────────
# Development: Ollama on any machine
# Production:  Lemonade Server on AMD Ryzen AI

LLM_PROVIDER = "ollama"  # "ollama" for dev, "lemonade" for AMD

# Ollama settings (development)
OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_MODEL = "llama3.2:3b"

# Lemonade settings (AMD Ryzen AI production)
LEMONADE_BASE_URL = "http://localhost:8000/api/v1"
LEMONADE_MODEL = "Llama-3.2-3B-Instruct-Hybrid"

# Active settings (auto-selected based on provider)
if LLM_PROVIDER == "ollama":
    LLM_BASE_URL = OLLAMA_BASE_URL
    LLM_MODEL = OLLAMA_MODEL
    LLM_API_KEY = "ollama"  # Ollama doesn't need a real key
else:
    LLM_BASE_URL = LEMONADE_BASE_URL
    LLM_MODEL = LEMONADE_MODEL
    LLM_API_KEY = "lemonade"


# ─── Whisper / Speech-to-Text ─────────────────────────────────────
# Development: Ollama's Whisper or disable STT
# Production:  Lemonade's Whisper on NPU
STT_ENABLED = False  # Set True when Whisper is available
STT_BASE_URL = LLM_BASE_URL
STT_MODEL = "whisper-large-v3-turbo"


# ─── RAG Configuration ────────────────────────────────────────────
KNOWLEDGE_BASE_DIR = "knowledge_base"
VECTOR_STORE_DIR = "vector_store"

# Embedding model (runs locally via HuggingFace — no API needed)
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"

# How many knowledge base chunks to retrieve per query
RAG_TOP_K = 5


# ─── Analysis Settings ────────────────────────────────────────────
LLM_TEMPERATURE = 0.2      # Low temperature = more consistent analysis
LLM_MAX_TOKENS = 800       # Enough for detailed analysis
SUPPORTED_LANGUAGES = ["english", "hindi", "telugu"]


# ─── UI Configuration ─────────────────────────────────────────────
APP_TITLE = "SHIELD"
APP_ICON = "🛡️"
APP_TAGLINE = "On-Device AI Fraud Detection for Indian UPI Users"

# Network monitor refresh interval (seconds)
NETWORK_MONITOR_INTERVAL = 2


# ─── Known Cloud AI Endpoints (for network monitor) ──────────────
# If any of these appear in outbound connections, we flag it
CLOUD_AI_ENDPOINTS = [
    "api.openai.com",
    "api.anthropic.com",
    "api.cohere.ai",
    "generativelanguage.googleapis.com",
    "api.together.xyz",
    "api.groq.com",
    "api.mistral.ai",
    "api.replicate.com",
]
