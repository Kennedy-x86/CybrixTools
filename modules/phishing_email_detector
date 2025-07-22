#!/usr/bin/python3

import re

# Phishing keywords with weights (0–1)
suspicious_keywords = {
    "urgent": 0.9,
    "suspended": 0.8,
    "click here": 0.85,
    "deleted": 0.75,
    "verify your account": 0.95,
    "login immediately": 0.85,
    "update payment": 0.9,
    "limited time": 0.7,
    "action required": 0.8
}

def check_email(email):
    email_lower = email.lower()
    score = 0
    matched_keywords = []

    for keyword, weight in suspicious_keywords.items():
        if keyword in email_lower:
            score += weight
            matched_keywords.append(f"Found: '{keyword}' (+{int(weight*100)}%)")

    percentage = min(int(score / len(suspicious_keywords) * 100), 100)

    # Classification thresholds
    if percentage >= 75:
        verdict = "High Risk – Likely Phishing"
        color = "red"
    elif percentage >= 40:
        verdict = "Moderate Risk – Possibly Suspicious"
        color = "orange"
    else:
        verdict = "Low Risk – Safe"
        color = "green"

    return {
        "score": percentage,
        "verdict": verdict,
        "color": color,
        "matches": matched_keywords
    }

def main():
    print("Phishing Email Detector for Cybrix Tools")
    email_text = input("Paste email text:\n")

    result = check_email(email_text)
    print("\nResult:")
    print(f"Risk Score: {result['score']}%")
    print(f"Verdict: {result['verdict']}\n")
    for match in result['matches']:
        print(match)

if __name__ == "__main__":
    main()