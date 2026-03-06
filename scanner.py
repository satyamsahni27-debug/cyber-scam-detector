import whois
import re

def scan_data(url, message):

    result = {}

    # -------- URL SCAN --------
    if url:

        try:
            domain = whois.whois(url)
            result["domain_age"] = str(domain.creation_date)

        except:
            result["domain_age"] = "Unknown"

        suspicious_words = ["login", "secure", "verify", "bank", "update", "account"]

        if any(word in url.lower() for word in suspicious_words):
            result["url_risk"] = "⚠ Suspicious Link"
        else:
            result["url_risk"] = "✅ Link looks safe"


    # -------- MESSAGE SCAN --------
    if message:

        message_lower = message.lower()

        scam_keywords = [
            "loan approved",
            "click here",
            "verify account",
            "urgent",
            "otp",
            "kyc",
            "bank account",
            "payment link"
        ]

        # URL detect in message
        url_pattern = r"http[s]?://"

        if any(word in message_lower for word in scam_keywords) or re.search(url_pattern, message_lower):
            result["message_risk"] = "🚨 Possible Scam Message"
        else:
            result["message_risk"] = "✅ Message looks safe"

    return result