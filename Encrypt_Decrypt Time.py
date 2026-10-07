import time
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # type: ignore
import os

# Define the encryption function
def encrypt_record(record, key):
    """
    Encrypt a record using AES-GCM.
    Args:
        record (dict): The record to encrypt.
        key (bytes): The AES key (32 bytes for AES-256).
    Returns:
        dict: A dictionary containing the ciphertext and nonce.
    """
    plaintext = json.dumps(record).encode('utf-8')
    nonce = os.urandom(12)  # 12-byte nonce for AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {"ciphertext": ciphertext, "nonce": nonce}

# Define the decryption function
def decrypt_record(encrypted, key):
    """
    Decrypt a record using AES-GCM.
    Args:
        encrypted (dict): The encrypted record containing ciphertext and nonce.
        key (bytes): The AES key (32 bytes for AES-256).
    Returns:
        dict: The decrypted record as a dictionary.
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(encrypted["nonce"], encrypted["ciphertext"], None)
    return json.loads(plaintext.decode('utf-8'))

# Example record and key
record = {
    "patient_id": "12345",
    "name": "John Doe",
    "diagnosis": "Flu",
    "treatment": "Rest and hydration"
}
key = os.urandom(32)  # Generate a random 256-bit AES key

# Measure encryption time for a record
start_time = time.perf_counter()
encrypted = encrypt_record(record, key)
encryption_time = time.perf_counter() - start_time
print(f"Encryption time: {encryption_time:.4f} seconds")

# Measure decryption time for the record
start_time = time.perf_counter()
decrypted = decrypt_record(encrypted, key)
decryption_time = time.perf_counter() - start_time
print(f"Decryption time: {decryption_time:.4f} seconds")

# Verify the decryption result
assert decrypted == record, "Decryption failed: The decrypted record does not match the original."
print("Decryption successful!")