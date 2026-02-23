URGENCY_PATTERNS = {
    "english": [
        ("immediately", 30, "time_pressure"),
        ("urgent", 30, "time_pressure"),
        ("within 24 hours", 40, "time_pressure"),
        ("within 2 hours", 45, "time_pressure"),
        ("expiring today", 35, "time_pressure"),
        ("act now", 30, "time_pressure"),
        ("right away", 25, "time_pressure"),
        ("as soon as possible", 20, "time_pressure"),
        ("time is running out", 35, "time_pressure"),
        ("deadline", 25, "time_pressure"),
        ("last chance", 35, "time_pressure"),
        ("limited time", 30, "time_pressure"),

        ("account will be blocked", 50, "account_threat"),
        ("account will be suspended", 50, "account_threat"),
        ("account will be deactivated", 45, "account_threat"),
        ("account will be closed", 45, "account_threat"),
        ("account has been compromised", 40, "account_threat"),
        ("unauthorized transaction", 35, "account_threat"),
        ("suspicious activity", 30, "account_threat"),
        ("security alert", 25, "account_threat"),

        ("legal action", 40, "legal_threat"),
        ("police complaint", 45, "legal_threat"),
        ("arrest warrant", 50, "legal_threat"),
        ("court order", 45, "legal_threat"),
        ("cbi", 45, "legal_threat"),
        ("income tax department", 40, "legal_threat"),
        ("enforcement directorate", 45, "legal_threat"),
        ("cyber cell", 35, "legal_threat"),
        ("failure to comply", 35, "legal_threat"),
        ("penalty", 30, "legal_threat"),

        ("verify now", 35, "action_demand"),
        ("click here", 25, "action_demand"),
        ("update your", 25, "action_demand"),
        ("confirm your", 25, "action_demand"),
        ("call this number", 30, "action_demand"),
        ("download this app", 35, "action_demand"),

        ("you have won", 40, "greed_trigger"),
        ("congratulations", 30, "greed_trigger"),
        ("cashback", 20, "greed_trigger"),
        ("reward", 20, "greed_trigger"),
        ("prize", 35, "greed_trigger"),
        ("lucky winner", 40, "greed_trigger"),
        ("selected for", 30, "greed_trigger"),
        ("guaranteed return", 40, "greed_trigger"),
        ("double your money", 45, "greed_trigger"),
        ("investment opportunity", 30, "greed_trigger"),
    ],

    "hindi": [
        ("turant", 30, "time_pressure"),
        ("jaldi kare", 30, "time_pressure"),
        ("jaldi karein", 30, "time_pressure"),
        ("abhi", 20, "time_pressure"),
        ("24 ghante", 40, "time_pressure"),
        ("2 ghante mein", 45, "time_pressure"),
        ("aakhri mauka", 35, "time_pressure"),
        ("aakhri chetavni", 40, "time_pressure"),
        ("samay seema", 30, "time_pressure"),
        ("jald se jald", 25, "time_pressure"),
        ("fauran", 30, "time_pressure"),

        ("band ho jayega", 50, "account_threat"),
        ("block ho jayega", 45, "account_threat"),
        ("suspend ho jayega", 45, "account_threat"),
        ("khata band", 45, "account_threat"),
        ("account band", 45, "account_threat"),
        ("khata freeze", 40, "account_threat"),

        ("kanooni karwai", 40, "legal_threat"),
        ("police", 40, "legal_threat"),
        ("giraftaar", 50, "legal_threat"),
        ("arrest", 50, "legal_threat"),
        ("kanoon ke mutabiq", 35, "legal_threat"),
        ("court", 40, "legal_threat"),
        ("adalat", 40, "legal_threat"),
        ("jurmana", 30, "legal_threat"),

        ("verify karein", 35, "action_demand"),
        ("verify kare", 35, "action_demand"),
        ("update karein", 25, "action_demand"),
        ("click karein", 25, "action_demand"),
        ("yahan dabayein", 25, "action_demand"),
        ("call karein", 30, "action_demand"),
        ("phone karein", 30, "action_demand"),

        ("aapne jeeta hai", 40, "greed_trigger"),
        ("badhai ho", 30, "greed_trigger"),
        ("inam", 35, "greed_trigger"),
        ("cashback", 20, "greed_trigger"),
        ("paisa double", 45, "greed_trigger"),
        ("munafa", 30, "greed_trigger"),
        ("guaranteed return", 40, "greed_trigger"),
    ],

    "telugu": [
        ("ventane", 30, "time_pressure"),
        ("vegam ga", 25, "time_pressure"),
        ("ippudu", 20, "time_pressure"),
        ("24 gantallo", 40, "time_pressure"),

        ("account block", 45, "account_threat"),
        ("khata band", 45, "account_threat"),
        ("suspend avutundi", 45, "account_threat"),

        ("police case", 45, "legal_threat"),
        ("arrest", 50, "legal_threat"),
        ("court notice", 45, "legal_threat"),
        ("chattaparamaina", 35, "legal_threat"),

        ("verify cheyandi", 35, "action_demand"),
        ("click cheyandi", 25, "action_demand"),
        ("update cheyandi", 25, "action_demand"),
    ],
}

PIN_OTP_PATTERNS = [
    "share your pin", "enter your pin", "send your pin",
    "share your otp", "send otp", "enter otp", "otp share",
    "share otp", "your otp is", "verify otp",
    "share your cvv", "enter cvv", "cvv number",
    "share password", "enter password", "send password",
    "share your upi pin", "enter upi pin",
    "mpin", "share mpin",
    "pin batayein", "pin bhejein", "pin share karein",
    "otp batayein", "otp bhejein", "otp share karein",
    "apna pin", "apna otp", "apna password",
    "gupt code", "guptank",
    "pin cheppandi", "otp cheppandi", "pin ivvandi",
]

SENSITIVE_KEYWORDS = ["pin", "otp", "cvv", "mpin", "password", "passcode"]


def classify_urgency(message: str) -> dict:
    msg_lower = message.lower()

    pin_otp_requested = _check_pin_otp_request(msg_lower)

    tactics_found = []
    total_score = 0
    tactic_categories = {}

    for language, patterns in URGENCY_PATTERNS.items():
        for phrase, score, tactic_type in patterns:
            if phrase in msg_lower:
                tactics_found.append({
                    "phrase": phrase,
                    "language": language,
                    "score": score,
                    "tactic": tactic_type,
                })
                total_score += score

                if tactic_type not in tactic_categories:
                    tactic_categories[tactic_type] = 0
                tactic_categories[tactic_type] += 1

    if pin_otp_requested:
        total_score = 100
        tactics_found.insert(0, {
            "phrase": "PIN/OTP/CVV request detected",
            "language": "universal",
            "score": 100,
            "tactic": "credential_theft",
        })
        tactic_categories["credential_theft"] = 1

    total_score = min(total_score, 100)

    if pin_otp_requested or total_score >= 80:
        level = "CRITICAL"
    elif total_score >= 50:
        level = "HIGH"
    elif total_score >= 25:
        level = "MEDIUM"
    elif total_score > 0:
        level = "LOW"
    else:
        level = "NONE"

    summary = _build_summary(level, pin_otp_requested, tactics_found, tactic_categories)

    return {
        "urgency_detected": len(tactics_found) > 0,
        "level": level,
        "score": total_score,
        "tactics_found": tactics_found,
        "pin_otp_requested": pin_otp_requested,
        "tactic_categories": tactic_categories,
        "summary": summary,
    }


def _check_pin_otp_request(msg_lower: str) -> bool:
    for phrase in PIN_OTP_PATTERNS:
        if phrase in msg_lower:
            return True

    action_words = [
        "share", "send", "enter", "tell", "give", "provide",
        "type", "input", "submit", "bhejein", "batayein",
        "karein", "dijiye", "cheppandi", "ivvandi",
    ]

    for keyword in SENSITIVE_KEYWORDS:
        if keyword in msg_lower:
            for action in action_words:
                if action in msg_lower:
                    kw_pos = msg_lower.find(keyword)
                    act_pos = msg_lower.find(action)
                    if abs(kw_pos - act_pos) <= 30:
                        return True

    return False


def _build_summary(level, pin_otp, tactics, categories):
    if level == "NONE":
        return "No urgency manipulation detected in this message."

    parts = []

    if pin_otp:
        parts.append(
            "CRITICAL: This message asks for your PIN, OTP, or CVV. "
            "No legitimate bank or UPI service will EVER request these "
            "via SMS, call, or message. This is definitely fraud."
        )
    elif level == "CRITICAL":
        parts.append(
            "CRITICAL: This message uses extreme psychological pressure "
            "to make you act without thinking."
        )
    elif level == "HIGH":
        parts.append(
            "HIGH RISK: Multiple urgency tactics detected. "
            "Scammers are trying to rush you into action."
        )

    if "account_threat" in categories:
        parts.append("Threatens to block/suspend your account — a classic scare tactic.")
    if "legal_threat" in categories:
        parts.append("Uses legal/police threats — real authorities never threaten via SMS.")
    if "time_pressure" in categories:
        parts.append("Creates artificial time pressure — real bank issues don't expire in hours.")
    if "greed_trigger" in categories:
        parts.append("Promises rewards or prizes — if you didn't enter a contest, you didn't win.")
    if "action_demand" in categories:
        parts.append("Demands immediate action (click/call/verify) — take a breath, verify independently.")

    return " ".join(parts)


if __name__ == "__main__":
    test_messages = [
        "Dear customer, your SBI account is under review. "
        "Please share your UPI PIN to verify your identity.",

        "URGENT: Your HDFC account will be blocked within 24 hours. "
        "Update KYC immediately to avoid suspension.",

        "Aapka SBI khata 24 ghante mein band ho jayega. "
        "Turant verify karein: http://bit.ly/sbi-verify",

        "Congratulations! You have won Rs 50,000 cashback. "
        "Click here to claim your reward.",

        "Please update your account details at your earliest convenience.",

        "Your SBI account XXX1234 has been credited with Rs 5,000 "
        "on 21-Feb-2026. Available balance: Rs 25,430.",

        "This is CBI calling. An arrest warrant has been issued "
        "against you for money laundering. Call this number immediately "
        "or face legal action within 2 hours.",
    ]

    for msg in test_messages:
        result = classify_urgency(msg)
        print(f"\n{'='*60}")
        print(f"Message: {msg[:80]}...")
        print(f"Level: {result['level']} | Score: {result['score']}/100")
        print(f"PIN/OTP Request: {'YES' if result['pin_otp_requested'] else 'No'}")
        print(f"Summary: {result['summary']}")
        if result["tactics_found"]:
            print(f"Tactics ({len(result['tactics_found'])}):")
            for t in result["tactics_found"][:5]:
                print(f"  [{t['language']}] \"{t['phrase']}\" -> {t['tactic']} (+{t['score']})")
