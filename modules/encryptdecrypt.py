from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def derive_key(pw: str) -> bytes:
    """
    Gets 256 bit AES key from password using SHA 256 hash
    """

    from hashlib import sha256
    return sha256(pw.encode()).digest()

def encrypt_data(key: bytes, text: bytes) -> bytes:
    """
    Will encrypt text bytes using AES GCM with key
    Creates random 12 byte nonce and prepends to ciphertext
    Returns nonce and bytes
    """

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, text, None)
    return nonce + ct

def decrypt_data(key: bytes, ciphertext: bytes) -> bytes:
    """
    Will decrypt ciphertext bytes using AES GCM with key
    Creates random 12 bytes as nonce and the rest to ciphertext
    Returns decrypted text bytes
    """

    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    return aesgcm.decrypt(nonce, ct, None)

def save_encrypted(filepath: str, data: bytes):
    """
    Saves bytes data to file at specified path
    Used to save encrypted binary data
    """

    with open(filepath, "wb") as f:
        f.write(data)

def load_encrypted(filepath: str) -> bytes:
    """
    Loads and returns raw bytes data
    Used to read encryped binary files
    """

    with open(filepath, "rb") as f:
        return f.read()
