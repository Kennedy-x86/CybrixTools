#!/usr/bin/python3
import re

# Blacklisted common passwords
COMMON_PASSWORDS = {"password", "123456", "qwerty", "letmein", "admin", "welcome", "iloveyou", "123456789"}


def check_password_strength(password):
    score = 0
    feedback = []

    # Blacklist check
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("❌ Your password is too common.")
        return 1, feedback

    # Length score
    if len(password) >= 16:
        score += 2
        feedback.append("✅ Excellent length.")
    elif len(password) >= 12:
        score += 1
        feedback.append("✅ Good length.")
    else:
        feedback.append("❌ Password too short. Use at least 12 characters.")

    # Uppercase
    if re.search(r'[A-Z]', password):
        score += 1
        feedback.append("✅ Contains uppercase letters.")
    else:
        feedback.append("❌ Add uppercase letters.")

    # Lowercase
    if re.search(r'[a-z]', password):
        score += 1
        feedback.append("✅ Contains lowercase letters.")
    else:
        feedback.append("❌ Add lowercase letters.")

    # Digits
    if re.search(r'[0-9]', password):
        score += 1
        feedback.append("✅ Contains numbers.")
    else:
        feedback.append("❌ Add numbers.")

    # Special characters
    if re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        score += 1
        feedback.append("✅ Contains special characters.")
    else:
        feedback.append("❌ Add special characters.")

    # Repetition penalty
    if re.search(r'(.)\1\1', password):
        score -= 1
        feedback.append("⚠️ Avoid repeating characters (e.g., aaa, 111).")

    # Entropy estimate
    char_sets = 0
    if re.search(r'[a-z]', password): char_sets += 26
    if re.search(r'[A-Z]', password): char_sets += 26
    if re.search(r'[0-9]', password): char_sets += 10
    if re.search(r'[!@#$%^&*(),.?\":{}|<>]', password): char_sets += 32
    estimated_entropy = len(password) * (char_sets.bit_length() if char_sets else 1)

    if estimated_entropy < 50:
        feedback.append("⚠️ Entropy is low. Increase complexity or length.")
    else:
        score += 1
        feedback.append("✅ Good entropy level.")

    # Clamp score
    final_score = max(1, min(score, 10))
    return final_score, feedback


def run_main():
    print("\n🔐 Welcome to the OpenCyb3r Password Analyzer\n")
    password = input("Enter your password: ")

    score, feedback = check_password_strength(password)

    print(f"\n🔎 Password Strength Score: {score}/10")
    print("🧠 Feedback:")
    for msg in feedback:
        print(f"  - {msg}")

    print("\n✅ Done!\n")


if __name__ == "__main__":
    run_main()