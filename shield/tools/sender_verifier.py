"""
SHIELD — Sender ID Verifier Tool
==================================
Verifies whether a message sender ID matches known legitimate bank/UPI sender codes.

How it works:
    1. Extracts sender ID from the message (if present) or takes it as input
    2. Compares against a database of verified Indian bank sender IDs
    3. Checks for typosquatting (SB1BNK vs SBIBNK — swapped characters)
    4. Flags unknown or suspicious sender patterns

Why this matters:
    Scammers impersonate banks using sender IDs that look almost right.
    "SB1-OTP" instead of "SBIBNK", or "HDFC-ALERTS" instead of "HDFCBK".
    Most users don't notice the difference. This tool does.

Indian bank SMS sender IDs follow a pattern:
    - 6-character alphanumeric code (e.g., SBIBNK, HDFCBK)
    - Sometimes prefixed with XX- or AD- (e.g., AD-SBIBNK)
    - Transactional messages use different codes than promotional
"""

import re
from difflib import SequenceMatcher
from typing import Optional


LEGITIMATE_SENDERS = {
    "sbi": {
        "sender_ids": [
            "SBIBNK", "SBIPSG", "SBIINB", "SBIYNO", "SBIUNO",
            "SBISMA", "SBIBIN", "ATMSBI",
        ],
        "full_name": "State Bank of India",
    },
    "hdfc": {
        "sender_ids": [
            "HDFCBK", "HLOANS", "HDFCBN", "HDFCSB",
        ],
        "full_name": "HDFC Bank",
    },
    "icici": {
        "sender_ids": [
            "ICICIB", "ICICBA", "ICICIS", "ICICIP",
        ],
        "full_name": "ICICI Bank",
    },
    "axis": {
        "sender_ids": [
            "AXISBK", "AXISMB", "AXISBN",
        ],
        "full_name": "Axis Bank",
    },
    "kotak": {
        "sender_ids": [
            "KOTAKB", "KOTMAH", "KOTAK8",
        ],
        "full_name": "Kotak Mahindra Bank",
    },
    "pnb": {
        "sender_ids": [
            "PNBSMS", "PNBBNK",
        ],
        "full_name": "Punjab National Bank",
    },
    "bob": {
        "sender_ids": [
            "BOBTXN", "BOBSMS", "BBRODR",
        ],
        "full_name": "Bank of Baroda",
    },
    "canara": {
        "sender_ids": [
            "CANBNK", "CANBSM",
        ],
        "full_name": "Canara Bank",
    },
    "union": {
        "sender_ids": [
            "UBIOBC", "UBIBNK",
        ],
        "full_name": "Union Bank of India",
    },
    "idbi": {
        "sender_ids": [
            "IDBIBK", "IDBISM",
        ],
        "full_name": "IDBI Bank",
    },
    "paytm": {
        "sender_ids": [
            "PYTM", "PAYTMB", "PAYTMS",
        ],
        "full_name": "Paytm / Paytm Payments Bank",
    },
    "phonepe": {
        "sender_ids": [
            "PHONPE", "PHPHPE",
        ],
        "full_name": "PhonePe",
    },
    "gpay": {
        "sender_ids": [
            "GOOGLE", "GGLPAY",
        ],
        "full_name": "Google Pay",
    },
    "npci": {
        "sender_ids": [
            "NPCITX", "UPIBNK",
        ],
        "full_name": "National Payments Corporation of India",
    },
    "rbi": {
        "sender_ids": [
            "RBIBNK", "RBISAY",
        ],
        "full_name": "Reserve Bank of India",
    },
}

ALL_LEGITIMATE_IDS = set()
ID_TO_BANK = {}
for bank, info in LEGITIMATE_SENDERS.items():
    for sid in info["sender_ids"]:
        ALL_LEGITIMATE_IDS.add(sid.upper())
        ID_TO_BANK[sid.upper()] = info["full_name"]


def verify_sender(message: str, sender_id: Optional[str] = None) -> dict:
    """
    Verify whether a sender ID is from a legitimate bank.

    Args:
        message: The full message text (used to extract sender if not provided)
        sender_id: Optional explicit sender ID (e.g., "SBIBNK")

    Returns:
        dict with:
            - sender_detected: the sender ID found (or None)
            - is_verified: True if sender matches known legitimate bank
            - bank_name: name of the matched bank (if verified)
            - risk_score: 0-100 (0 = verified, 100 = definitely fake)
            - indicators: list of specific concerns
            - summary: human-readable explanation
    """
    if not sender_id:
        sender_id = _extract_sender_id(message)

    if not sender_id:
        claimed_bank = _detect_bank_claim(message)
        if claimed_bank:
            return {
                "sender_detected": None,
                "is_verified": False,
                "bank_name": None,
                "risk_score": 35,
                "indicators": [
                    f"Message claims to be from {claimed_bank} but no "
                    f"standard bank sender ID was found. Legitimate bank SMS "
                    f"always comes from a registered 6-character sender ID."
                ],
                "summary": f"No sender ID found, but message claims to be from {claimed_bank}. Exercise caution.",
            }
        return {
            "sender_detected": None,
            "is_verified": False,
            "bank_name": None,
            "risk_score": 0,
            "indicators": [],
            "summary": "No sender ID detected in message.",
        }

    sender_upper = sender_id.upper().strip()

    if sender_upper in ALL_LEGITIMATE_IDS:
        bank_name = ID_TO_BANK[sender_upper]
        return {
            "sender_detected": sender_upper,
            "is_verified": True,
            "bank_name": bank_name,
            "risk_score": 0,
            "indicators": [],
            "summary": f"Verified sender: {sender_upper} belongs to {bank_name}.",
        }

    closest_match, similarity = _find_closest_sender(sender_upper)
    indicators = []
    risk_score = 0

    if closest_match and similarity >= 0.7:
        real_bank = ID_TO_BANK[closest_match]
        indicators.append(
            f"Sender '{sender_upper}' is similar to '{closest_match}' ({real_bank}) "
            f"but is NOT an exact match. This could be a typosquatting attempt — "
            f"scammers use sender IDs that look almost identical to real bank codes."
        )
        risk_score += 60

    claimed_bank = _detect_bank_in_sender(sender_upper)
    if claimed_bank and not closest_match:
        indicators.append(
            f"Sender ID contains '{claimed_bank}' but is not in our verified "
            f"database. Could be a new legitimate code, but treat with caution."
        )
        risk_score += 40

    if not re.match(r'^[A-Z0-9]{4,8}$', sender_upper):
        indicators.append(
            f"Sender ID '{sender_upper}' doesn't follow standard Indian bank "
            f"SMS format (4-8 alphanumeric characters). Unusual format is suspicious."
        )
        risk_score += 25

    risk_score = min(risk_score, 100)

    if risk_score >= 50:
        summary = f"SUSPICIOUS: Sender '{sender_upper}' is not a verified bank sender ID."
    elif risk_score > 0:
        summary = f"UNVERIFIED: Sender '{sender_upper}' is not in our database. Exercise caution."
    else:
        summary = f"Sender '{sender_upper}' is unknown — not in our verified database."
        risk_score = 20  

    return {
        "sender_detected": sender_upper,
        "is_verified": False,
        "bank_name": None,
        "risk_score": risk_score,
        "indicators": indicators,
        "summary": summary,
    }


def _extract_sender_id(message: str) -> Optional[str]:
    """
    Try to extract a sender ID from message text.
    Indian bank SMS often has the sender ID in the message header or
    is prefixed like "AD-SBIBNK" or "[SBIBNK]".
    """
    patterns = [
        r'^(?:AD|TD|TA|TM|VM|DM|SI)-([A-Z0-9]{4,8})',  # AD-SBIBNK
        r'\[([A-Z0-9]{4,8})\]',                          # [SBIBNK]
        r'^From:?\s*([A-Z0-9]{4,8})',                     # From: SBIBNK
    ]

    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def _detect_bank_claim(message: str) -> Optional[str]:
    """Detect if a message claims to be from a specific bank."""
    msg_lower = message.lower()
    bank_mentions = {
        "sbi": "State Bank of India",
        "hdfc": "HDFC Bank",
        "icici": "ICICI Bank",
        "axis": "Axis Bank",
        "kotak": "Kotak Bank",
        "pnb": "Punjab National Bank",
        "paytm": "Paytm",
        "phonepe": "PhonePe",
        "google pay": "Google Pay",
        "gpay": "Google Pay",
        "rbi": "Reserve Bank of India",
    }

    for keyword, bank_name in bank_mentions.items():
        if keyword in msg_lower:
            return bank_name
    return None


def _detect_bank_in_sender(sender_id: str) -> Optional[str]:
    """Check if a sender ID contains a known bank abbreviation."""
    sid_lower = sender_id.lower()
    for bank_name in LEGITIMATE_SENDERS.keys():
        if bank_name in sid_lower:
            return bank_name
    return None


def _find_closest_sender(sender_id: str) -> tuple[Optional[str], float]:
    """Find the closest matching legitimate sender ID using string similarity."""
    best_match = None
    best_score = 0.0

    for legitimate_id in ALL_LEGITIMATE_IDS:
        score = SequenceMatcher(None, sender_id, legitimate_id).ratio()
        if score > best_score:
            best_score = score
            best_match = legitimate_id

    return (best_match, best_score) if best_score >= 0.6 else (None, 0.0)


if __name__ == "__main__":
    test_cases = [
        ("AD-SBIBNK: Your a/c XXX1234 credited Rs 5,000.", None),

        ("", "SB1BNK"),  # 'I' replaced with '1'

        ("Dear HDFC customer, your account will be blocked. "
         "Update KYC now.", "HDFCAL"),

        ("Dear SBI customer, click here to verify your account.", None),

        ("Your order has been shipped.", "AMZN01"),

        ("", "PAYTMB"),
    ]

    for msg, sid in test_cases:
        result = verify_sender(msg, sid)
        print(f"\n{'='*60}")
        print(f"Message: {msg[:60]}..." if msg else f"Sender ID: {sid}")
        print(f"Sender: {result['sender_detected']}")
        print(f"Verified: {result['is_verified']}")
        if result["bank_name"]:
            print(f"Bank: {result['bank_name']}")
        print(f"Risk: {result['risk_score']}/100")
        print(f"Summary: {result['summary']}")
        for ind in result["indicators"]:
            print(f"  ⚠ {ind}")
