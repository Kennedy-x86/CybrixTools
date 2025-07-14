import pyotp
import json
from pathlib import Path

# Dynamically reference the file location to avoid hardcoding. Might change it.
BASE_DIR = Path(__file__).parent
SECRET_FILE = BASE_DIR / "totp_secret.json"

def ensure_secret_file_path():
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)

def generate_secret():
    """Generate and store a new TOTP secret"""
    ensure_secret_file_path()
    secret = pyotp.random_base32()
    data = {"secret": secret}
    SECRET_FILE.write_text(json.dumps(data))
    return secret

def load_secret():
    """Load existing TOTP secret"""
    if not SECRET_FILE.exists():
        return None
    data = json.loads(SECRET_FILE.read_text())
    return data.get("secret")

def get_totp_code(secret):
    """Generate the current TOTP code"""
    return pyotp.TOTP(secret).now()

def get_provisioning_uri(secret, name="user@cybrixtools", issuer="CybrixTools"):
    """Return the provisioning URI for QR code apps"""
    return pyotp.TOTP(secret).provisioning_uri(name=name, issuer_name=issuer)

def setup_totp():
    print("🔐 Setting up new TOTP secret...")
    secret = generate_secret()
    uri = get_provisioning_uri(secret)
    print("\n✅ Secret stored successfully!")
    print("📱 Use this URI in your Authenticator App:")
    print(uri)

def display_totp():
    secret = load_secret()
    if not secret:
        print("❌ No TOTP secret found. Please run setup first.")
        return
    code = get_totp_code(secret)
    print(f"✅ Your current TOTP code is: {code}")

def reset_totp_secret():
    if SECRET_FILE.exists():
        SECRET_FILE.unlink()
        print("✅ TOTP secret has been reset.")

def run_main():
    while True:
        print("""
TOTP Generator
=======================
1. First Time Setup
2. Get TOTP Code
3. Reset TOTP Secret
4. Exit
""")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            setup_totp()
        elif choice == "2":
            display_totp()
        elif choice == "3":
            reset_totp_secret()
        elif choice == "4":
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    run_main()