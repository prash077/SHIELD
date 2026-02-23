"""
SHIELD — URL Analyzer Tool
===========================
Detects phishing and suspicious URLs in messages.

How it works:
    1. Extracts all URLs from the message text
    2. Checks each URL against multiple red flag patterns:
       - URL shorteners (bit.ly, tinyurl — hide the real destination)
       - Bank name in non-official domain (sbi in bit.ly/sbi-kyc)
       - Suspicious TLDs (.xyz, .top, .click — cheap domains scammers love)
       - IP addresses instead of domain names (http://192.168.1.1/login)
       - Missing HTTPS (no encryption = no trust)
       - Misspelled bank domains (sbilbank.com vs sbibank.com)
    3. Returns a score (0-100) and list of specific indicators found

Why this matters:
    80%+ of phishing SMS contain a malicious link. Catching the URL
    alone can prevent most fraud. This tool runs in <1ms and gives
    the LLM concrete evidence to work with.
"""

import re
from typing import Optional


URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "rb.gy",
    "short.url", "cutt.ly", "is.gd", "v.gd", "tiny.cc",
    "ow.ly", "bl.ink", "soo.gd", "s.id", "rebrand.ly",
    "shorturl.at", "hyperurl.co",
]


OFFICIAL_BANK_DOMAINS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbicard.com"],
    "hdfc": ["hdfcbank.com", "hdfcsec.com"],
    "icici": ["icicibank.com", "icicidirect.com"],
    "axis": ["axisbank.com", "axisdirect.in"],
    "kotak": ["kotak.com", "kotaksecurities.com"],
    "pnb": ["pnbindia.in", "pnbnet.org.in"],
    "bob": ["bankofbaroda.in", "barodaetrade.com"],
    "canara": ["canarabank.com"],
    "union": ["unionbankofindia.co.in"],
    "idbi": ["idbibank.in"],
    "paytm": ["paytm.com", "paytmbank.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["pay.google.com"],
    "cred": ["cred.club"],
    "razorpay": ["razorpay.com"],
    "npci": ["npci.org.in"],
}


SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".buzz", ".info", ".online",
    ".site", ".fun", ".club", ".live", ".work", ".loan",
    ".win", ".bid", ".stream", ".racing", ".download",
    ".icu", ".cam", ".rest",
]


SUSPICIOUS_PATH_KEYWORDS = [
    "verify", "update", "confirm", "secure", "login",
    "account", "kyc", "refund", "claim", "reward",
    "prize", "winner", "offer", "free", "urgent",
]


def analyze_urls(message: str) -> dict:
    """
    Analyze all URLs found in a message for phishing indicators.

    Args:
        message: The suspicious message text

    Returns:
        dict with:
            - urls_found: number of URLs detected
            - analyses: list of per-URL analysis results
            - overall_risk: highest risk score across all URLs (0-100)
            - summary: human-readable summary of findings
    """
    urls = _extract_urls(message)

    if not urls:
        return {
            "urls_found": 0,
            "analyses": [],
            "overall_risk": 0,
            "summary": "No URLs found in message.",
        }

    analyses = [_analyze_single_url(url, message) for url in urls]
    overall_risk = max(a["risk_score"] for a in analyses)

    if overall_risk >= 80:
        summary = f"DANGEROUS: {len(urls)} URL(s) found with critical phishing indicators."
    elif overall_risk >= 50:
        summary = f"SUSPICIOUS: {len(urls)} URL(s) found with multiple red flags."
    elif overall_risk >= 25:
        summary = f"CAUTION: {len(urls)} URL(s) found with minor concerns."
    else:
        summary = f"{len(urls)} URL(s) found. No significant phishing indicators."

    return {
        "urls_found": len(urls),
        "analyses": analyses,
        "overall_risk": overall_risk,
        "summary": summary,
    }


def _extract_urls(text: str) -> list[str]:
    """Extract URLs from text, including partial URLs that scammers use."""
    standard = re.findall(
        r'https?://[^\s<>"\')\]]+',
        text, re.IGNORECASE,
    )

    no_protocol = re.findall(
        r'(?:www\.|bit\.ly/|tinyurl\.com/|goo\.gl/|t\.co/)[^\s<>"\')\]]+',
        text, re.IGNORECASE,
    )

    seen = set()
    urls = []
    for url in standard + no_protocol:
        url_clean = url.rstrip(".,;:!?")  
        if url_clean.lower() not in seen:
            seen.add(url_clean.lower())
            urls.append(url_clean)

    return urls


def _analyze_single_url(url: str, full_message: str) -> dict:
    """Analyze a single URL for phishing indicators."""
    url_lower = url.lower()
    risk_score = 0
    indicators = []

    for shortener in URL_SHORTENERS:
        if shortener in url_lower:
            indicators.append(
                f"Uses URL shortener ({shortener}) — hides real destination. "
                f"Banks never use shortened links in official messages."
            )
            risk_score += 40
            break  

    matched_bank = _check_bank_name_abuse(url_lower)
    if matched_bank:
        indicators.append(
            f"Contains '{matched_bank}' but is NOT an official {matched_bank.upper()} domain. "
            f"This is a common phishing tactic — using bank names in fake URLs."
        )
        risk_score += 45

    for tld in SUSPICIOUS_TLDS:
        if url_lower.endswith(tld) or (tld + "/") in url_lower:
            indicators.append(
                f"Uses suspicious domain extension ({tld}). "
                f"These cheap domains are heavily favored by scammers."
            )
            risk_score += 30
            break

    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        indicators.append(
            "URL uses a raw IP address instead of a domain name. "
            "Legitimate banking sites always use proper domain names."
        )
        risk_score += 45

    if url_lower.startswith("http://"):
        indicators.append(
            "Not using HTTPS (no encryption). "
            "All legitimate banking sites use HTTPS."
        )
        risk_score += 20

    path_hits = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in url_lower]
    if len(path_hits) >= 2:
        indicators.append(
            f"URL path contains suspicious keywords: {', '.join(path_hits)}. "
            f"Common in phishing URLs designed to look like bank actions."
        )
        risk_score += 15


    domain_part = _extract_domain(url)
    if domain_part and domain_part.count(".") >= 3:
        indicators.append(
            "URL has unusually many subdomains — often used to bury "
            "the real domain and make the URL look legitimate."
        )
        risk_score += 20

    risk_score = min(risk_score, 100)

    return {
        "url": url,
        "risk_score": risk_score,
        "indicators": indicators,
        "is_dangerous": risk_score >= 60,
    }


def _check_bank_name_abuse(url_lower: str) -> Optional[str]:
    """Check if a bank name appears in a non-official domain."""
    domain = _extract_domain(url_lower)
    if not domain:
        return None

    for bank_name, official_domains in OFFICIAL_BANK_DOMAINS.items():
        if bank_name in url_lower:
            is_official = any(
                domain == official or domain.endswith("." + official)
                for official in official_domains
            )
            if not is_official:
                return bank_name

    return None


def _extract_domain(url: str) -> Optional[str]:
    """Extract the domain from a URL."""
    domain = re.sub(r'^https?://', '', url.lower())
    domain = domain.split('/')[0]
    domain = domain.split(':')[0]
    return domain if domain else None


if __name__ == "__main__":
    test_messages = [
        "Dear SBI customer, your account will be blocked. "
        "Update KYC immediately: http://bit.ly/sbi-kyc-update",

        "HDFC Alert: Unusual activity detected. "
        "Verify now: https://hdfc-secure-login.xyz/verify",

        "Your SBI account has been credited with Rs 5,000. "
        "Check balance at https://onlinesbi.sbi",

        "URGENT: Click http://192.168.45.12/icici-login to secure your account",

        "Your OTP is 483920. Do not share with anyone.",
    ]

    for msg in test_messages:
        print(f"\n{'='*60}")
        print(f"Message: {msg[:80]}...")
        result = analyze_urls(msg)
        print(f"Risk: {result['overall_risk']}/100")
        print(f"Summary: {result['summary']}")
        for analysis in result["analyses"]:
            print(f"  URL: {analysis['url']}")
            for ind in analysis["indicators"]:
                print(f"{ind}")
