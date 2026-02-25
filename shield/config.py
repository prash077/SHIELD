
LLM_PROVIDER = "ollama"  

OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_MODEL = "llama3.2:1b"

LEMONADE_BASE_URL = "http://localhost:8000/api/v1"
LEMONADE_MODEL = "Llama-3.2-3B-Instruct-Hybrid"

if LLM_PROVIDER == "ollama":
    LLM_BASE_URL = OLLAMA_BASE_URL
    LLM_MODEL = OLLAMA_MODEL
    LLM_API_KEY = "ollama"  
else:
    LLM_BASE_URL = LEMONADE_BASE_URL
    LLM_MODEL = LEMONADE_MODEL
    LLM_API_KEY = "lemonade"


STT_ENABLED = False  
STT_BASE_URL = LLM_BASE_URL
STT_MODEL = "whisper-large-v3-turbo"


KNOWLEDGE_BASE_DIR = "knowledge_base"
VECTOR_STORE_DIR = "vector_store"

EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"

RAG_TOP_K = 5


LLM_TEMPERATURE = 0.2      
LLM_MAX_TOKENS = 500       
SUPPORTED_LANGUAGES = ["english", "hindi", "telugu"]


APP_TITLE = "SHIELD"
APP_ICON = "🛡️"
APP_TAGLINE = "On-Device AI Fraud Detection for Indian UPI Users"

NETWORK_MONITOR_INTERVAL = 2


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
