import json
from openai import OpenAI

import config
from tools.url_analyzer import analyze_urls
from tools.sender_verifier import verify_sender
from tools.urgency_classifier import classify_urgency


SYSTEM_PROMPT = """You are SHIELD, an expert AI fraud analyst specializing in Indian UPI and digital payment scams.

You will receive:
1. A suspicious message from a user
2. Results from automated analysis tools (URL check, sender verification, urgency detection)
3. Relevant fraud patterns from our knowledge base

Your job is to synthesize ALL of this information and provide a clear, actionable fraud analysis.

OUTPUT FORMAT (follow this exactly):

RISK SCORE: [0-100]%
FRAUD CATEGORY: [One of: Phishing SMS | Digital Arrest Scam | UPI Collect Fraud | KYC Scam | Investment Fraud | QR Code Scam | Fake Customer Care | Lottery Scam | Legitimate | Unclear]
CONFIDENCE: [High | Medium | Low]

RED FLAGS:
- [List each specific red flag found, one per line]

EXPLANATION:
[2-3 sentences explaining WHY this is or isn't a scam, in simple language. If the message is in Hindi or Telugu, write the explanation in that same language.]

RECOMMENDED ACTION:
[What the user should do — be specific]

RULES:
- If the message asks for PIN, OTP, or CVV — it is ALWAYS fraud, risk 100%
- If the message contains a suspicious URL — risk is at least 70%
- If the message threatens account blocking with a deadline — risk is at least 60%
- Legitimate bank transaction alerts (credited/debited with balance) are safe
- When unsure, err on the side of caution and flag it
- Respond in the SAME LANGUAGE as the input message"""


class FraudAnalyzer:
    def __init__(self, rag_engine=None):
        self.client = OpenAI(
            base_url=config.LLM_BASE_URL,
            api_key=config.LLM_API_KEY,
        )
        self.model = config.LLM_MODEL
        self.rag_engine = rag_engine

    def analyze(self, message: str, sender_id: str = None) -> dict:
        tool_results = self._run_tools(message, sender_id)

        rag_results = self._get_rag_context(message)

        llm_prompt = self._build_prompt(message, tool_results, rag_results)

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": llm_prompt},
                ],
                temperature=config.LLM_TEMPERATURE,
                max_tokens=config.LLM_MAX_TOKENS,
            )
            llm_analysis = response.choices[0].message.content
        except Exception as e:
            llm_analysis = f"LLM analysis unavailable: {str(e)}"

        combined_risk = self._calculate_combined_risk(tool_results)

        return {
            "message": message,
            "tool_results": tool_results,
            "rag_sources": [r["source"] for r in rag_results],
            "llm_analysis": llm_analysis,
            "combined_tool_risk": combined_risk,
            "model_used": self.model,
            "cloud_connections": 0,
        }

    def _run_tools(self, message: str, sender_id: str = None) -> dict:
        return {
            "url_analysis": analyze_urls(message),
            "sender_verification": verify_sender(message, sender_id),
            "urgency_analysis": classify_urgency(message),
        }

    def _get_rag_context(self, message: str) -> list[dict]:
        if self.rag_engine is None:
            return []
        try:
            return self.rag_engine.retrieve(message, top_k=config.RAG_TOP_K)
        except Exception as e:
            print(f"RAG retrieval failed: {e}")
            return []

    def _build_prompt(self, message: str, tools: dict, rag: list) -> str:
        url = tools["url_analysis"]
        sender = tools["sender_verification"]
        urgency = tools["urgency_analysis"]

        tool_summary = f"""AUTOMATED TOOL RESULTS:

URL Analysis:
  URLs found: {url['urls_found']}
  Risk: {url['overall_risk']}/100
  Summary: {url['summary']}"""

        if url["analyses"]:
            for a in url["analyses"]:
                tool_summary += f"\n  URL: {a['url']} (risk: {a['risk_score']})"
                for ind in a["indicators"]:
                    tool_summary += f"\n    - {ind}"

        tool_summary += f"""

Sender Verification:
  Sender: {sender['sender_detected']}
  Verified: {sender['is_verified']}
  Bank: {sender.get('bank_name', 'N/A')}
  Risk: {sender['risk_score']}/100
  Summary: {sender['summary']}"""

        tool_summary += f"""

Urgency Analysis:
  Level: {urgency['level']}
  Score: {urgency['score']}/100
  PIN/OTP Requested: {urgency['pin_otp_requested']}
  Summary: {urgency['summary']}"""

        rag_context = ""
        if rag:
            rag_context = "\n\nRELEVANT FRAUD PATTERNS FROM KNOWLEDGE BASE:\n"
            for i, r in enumerate(rag[:3]):
                rag_context += f"\n[Source: {r['source']}]\n{r['text'][:500]}\n"

        prompt = f"""SUSPICIOUS MESSAGE TO ANALYZE:
\"{message}\"

{tool_summary}
{rag_context}

Based on ALL the above information, provide your complete fraud analysis."""

        return prompt

    def _calculate_combined_risk(self, tools: dict) -> int:
        url_risk = tools["url_analysis"]["overall_risk"]
        sender_risk = tools["sender_verification"]["risk_score"]
        urgency_risk = tools["urgency_analysis"]["score"]

        if tools["urgency_analysis"]["pin_otp_requested"]:
            return 100

        combined = max(url_risk, sender_risk, urgency_risk)

        if url_risk > 0 and urgency_risk > 0:
            combined = min(combined + 15, 100)
        if url_risk > 0 and sender_risk > 0:
            combined = min(combined + 10, 100)

        return combined


if __name__ == "__main__":
    from pipeline.rag import RAGEngine

    print("SHIELD Fraud Analyzer")
    print("=" * 60)
    print(f"Model: {config.LLM_MODEL}")
    print(f"Provider: {config.LLM_PROVIDER}")
    print(f"API: {config.LLM_BASE_URL}")
    print("=" * 60)

    print("\nLoading RAG engine...")
    rag = RAGEngine()
    rag.build_index()

    analyzer = FraudAnalyzer(rag_engine=rag)

    test_messages = [
        "Dear SBI customer, your account will be blocked in 24hrs. "
        "Update KYC immediately: http://bit.ly/sbi-kyc-update",

        "Your a/c no. XXXXXXX1234 is credited by Rs.5,000.00 on "
        "21-Feb-26. Avl Bal Rs.25,430.50 -SBI",

        "This is CBI calling. An arrest warrant has been issued "
        "against you. Transfer Rs 50,000 to this account immediately "
        "or you will be arrested within 2 hours.",
    ]

    for msg in test_messages:
        print(f"\n{'='*60}")
        print(f"MESSAGE: {msg[:80]}...")
        print(f"{'='*60}")

        result = analyzer.analyze(msg)

        print(f"\nTool Risk: {result['combined_tool_risk']}/100")
        print(f"RAG Sources: {result['rag_sources']}")
        print(f"\nLLM Analysis:\n{result['llm_analysis']}")
        print(f"\nCloud Connections: {result['cloud_connections']}")
