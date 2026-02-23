"""
SHIELD Tools — Deterministic Fraud Detection
=============================================
These tools run WITHOUT any AI/LLM. They produce hard evidence
(scores + specific red flags) that feeds into the LLM analysis.

Usage:
    from tools.url_analyzer import analyze_urls
    from tools.sender_verifier import verify_sender
    from tools.urgency_classifier import classify_urgency
"""

from tools.url_analyzer import analyze_urls
from tools.sender_verifier import verify_sender
from tools.urgency_classifier import classify_urgency

__all__ = ["analyze_urls", "verify_sender", "classify_urgency"]