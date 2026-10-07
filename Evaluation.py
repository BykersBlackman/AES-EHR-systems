import os
import time
import secrets
import numpy as np
import matplotlib.pyplot as plt
from faker import Faker
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask
import unittest
import json
output_dir = r'C:\Users\Blackman\EvaluationPlots'
os.makedirs(output_dir, exist_ok=True)

# ------------------------------------------------------------------------------------------------
# For this evaluation, we assume that the core functions and globals have been imported.
# In this example, we re-create minimal versions of some functions (encrypt_record, decrypt_record)
# and required globals from AESCTX.py to enable testing.
# ------------------------------------------------------------------------------------------------

# Data comes from the shared generator so evaluation uses the same correlated
# dataset as the live system (AESCTX.py).
from synthetic_data import (  # type: ignore
    build_dataset,
    generate_synthetic_ehr_records_by_role,
    ROLES,
    CLINICAL_DEPARTMENTS as DEPARTMENTS,
)

staff_members, patients, _dataset_records = build_dataset()

fake = Faker()

# --- AES Key Manager ---
class AESKeyManager:
    def __init__(self):
        self.keys = {}
    def generate_key(self):
        return os.urandom(32)
    def add_role_key(self, role):
        key = self.generate_key()
        self.keys[role] = (key, time.time())
    def rotate_key(self, role):
        if role in self.keys:
            new_key = self.generate_key()
            self.keys[role] = (new_key, time.time())
    def get_key(self, role):
        return self.keys.get(role, (None, None))[0]

key_manager = AESKeyManager()
for role in ROLES:
    key_manager.add_role_key(role)

# --- Synthetic Data (shared, correlated dataset) ---
# generate_synthetic_ehr_records_by_role is imported from synthetic_data and used
# by the scalability benchmark below; the correlated per-role sets come from
# build_dataset() above.
synthetic_records = _dataset_records

encrypted_records = {role: {} for role in ROLES}

def encrypt_record(record, key):
    plaintext = json.dumps(record).encode('utf-8')
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {"ciphertext": ciphertext, "nonce": nonce, "key_id": record["key_id"]}

def decrypt_record(encrypted_record, key):
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(encrypted_record["nonce"], encrypted_record["ciphertext"], None)
    return json.loads(plaintext.decode('utf-8'))

for role, records in synthetic_records.items():
    key = key_manager.get_key(role)
    for record in records:
        encrypted_records[role][record["ehr_id"]] = encrypt_record(record, key)

# --- Context-Aware Policy Engine with Extended Validations ---
class ContextAwareEngine:
    def __init__(self, key_manager):
        self.key_manager = key_manager
    def evaluate_access(self, user, record):
        if user['role'] != record['assigned_role']:
            return None
        if user.get('department') != record.get('department'):
            return None
        if int(user.get('grade', 0)) < int(record.get('min_grade', 0)):
            return None
        return self.key_manager.get_key(user['role'])
        
policy_engine = ContextAwareEngine(key_manager)

# ------------------------------------------------------------------------------------------------
# Testing/Evaluation Code & Visualization Functions
# ------------------------------------------------------------------------------------------------

# (1) Encryption/Decryption Overhead
def evaluate_encryption_decryption_overhead(iterations=1000):
    """Measure the time taken to encrypt and decrypt a single record over multiple iterations."""
    test_record = synthetic_records["doctor"][0]  # use the first doctor record for testing
    key = key_manager.get_key("doctor")
    
    encryption_times = []
    decryption_times = []
    
    for _ in range(iterations):
        start_enc = time.perf_counter()
        encrypted = encrypt_record(test_record, key)
        end_enc = time.perf_counter()
        encryption_times.append((end_enc - start_enc) * 1000)  # in ms

        start_dec = time.perf_counter()
        _ = decrypt_record(encrypted, key)
        end_dec = time.perf_counter()
        decryption_times.append((end_dec - start_dec) * 1000)  # in ms
        
    avg_enc = np.mean(encryption_times)
    avg_dec = np.mean(decryption_times)
    return encryption_times, decryption_times, avg_enc, avg_dec

def plot_encryption_decryption_overhead():
    enc_times, dec_times, avg_enc, avg_dec = evaluate_encryption_decryption_overhead()
    iterations = np.arange(1, len(enc_times)+1)
    
    plt.figure(figsize=(12, 8))
    plt.plot(iterations, enc_times, label=f'Encryption Time (avg: {avg_enc:.2f} ms)', color='blue', marker='o', markersize=4)
    plt.plot(iterations, dec_times, label=f'Decryption Time (avg: {avg_dec:.2f} ms)', color='green', marker='s', markersize=4)
    plt.title('Encryption and Decryption Overhead')
    plt.xlabel('Iteration')
    plt.ylabel('Time (ms)')
    plt.legend(fontsize=14)
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, 'encryption_decryption_overhead.png'), dpi=300, bbox_inches='tight')
    plt.close()

# (2) Authentication Latency Evaluation
def evaluate_authentication_latency(trials=100):
    """
    Simulate the OTP generation and verification process.
    We measure the time required to generate and verify OTP repeatedly.
    """
    otp_times = []
    for _ in range(trials):
        start = time.perf_counter()
        otp = secrets.token_hex(3)  # OTP generation
        # Simulate storing the OTP in the session:
        session_data = {"otp": otp}
        # Simulate verification by simply comparing:
        _ = (session_data["otp"] == otp)
        end = time.perf_counter()
        otp_times.append((end - start)*1000)
    avg_latency = np.mean(otp_times)
    return otp_times, avg_latency

def plot_authentication_latency():
    times, avg_latency = evaluate_authentication_latency()
    attempts = np.arange(1, len(times)+1)
    plt.figure(figsize=(12, 8))
    plt.plot(attempts, times, label=f'OTP Auth Latency (avg: {avg_latency:.2f} ms)', color='purple', marker='d', markersize=4)
    plt.title('Authentication Latency (OTP Generation & Verification)')
    plt.xlabel('Trial')
    plt.ylabel('Latency (ms)')
    plt.legend(fontsize=14)
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, 'authentication_latency.png'), dpi=300, bbox_inches='tight')
    plt.close()

# (3) Scalability Testing: Varying Number of Records
def evaluate_scalability():
    """
    Generate synthetic datasets of varying sizes and measure average encryption time.
    """
    sizes = [100, 300, 500, 800, 1000, 1500, 2000]
    avg_times = []
    
    for size in sizes:
        records = generate_synthetic_ehr_records_by_role("doctor", num_records=size)
        key = key_manager.get_key("doctor")
        times = []
        for record in records:
            start = time.perf_counter()
            _ = encrypt_record(record, key)
            end = time.perf_counter()
            times.append((end - start) * 1000)
        avg_times.append(np.mean(times))
    return sizes, avg_times

def plot_scalability():
    sizes, avg_times = evaluate_scalability()
    plt.figure(figsize=(12, 8))
    plt.plot(sizes, avg_times, marker='o', linestyle='-', color='teal', label='Avg Encryption Time (ms)')
    plt.title('Scalability: Avg Encryption Time vs Number of EHR Records')
    plt.xlabel('Number of Records')
    plt.ylabel('Average Encryption Time (ms)')
    plt.legend(fontsize=14)
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, 'scalability.png'), dpi=300, bbox_inches='tight')
    plt.close()

# (4) Security Robustness: Brute Force OTP Simulation
def simulate_brute_force_otp(attempts=1000):
    """
    Simulate a brute force attack on OTP.
    Generate random OTP guesses (6-digit hex) and measure cumulative attempts over time.
    (This is purely simulated; in a real scenario, the system would block after a few failures.)
    """
    cumulative_attempts = []
    times = []
    start_time = time.perf_counter()
    for i in range(1, attempts + 1):
        _ = secrets.token_hex(3)  # Generate a random OTP guess.
        cumulative_attempts.append(i)
        times.append((time.perf_counter() - start_time))
    return times, cumulative_attempts

def plot_brute_force_otp():
    times, attempts_list = simulate_brute_force_otp()
    plt.figure(figsize=(12, 8))
    plt.plot(times, attempts_list, marker='.', linestyle='-', color='red', label='Cumulative OTP Attempts')
    plt.title('Brute Force OTP Simulation: Attempts Over Time')
    plt.xlabel('Time (s)')
    plt.ylabel('Number of Attempts')
    plt.legend(fontsize=14)
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, 'brute_force_otp.png'), dpi=300, bbox_inches='tight')
    plt.close()

# (5) Usability Evaluation: Simulated End-to-End Flow Duration
def simulate_usability_flow(trials=50):
    """
    Simulate an end-to-end login and record access flow using Flask's test_client.
    Measure the time taken for a complete process including:
      - OTP request, OTP verification, and patient hash verification.
    For simulation purposes, we manually compute the time intervals.
    (In a real test, this would involve user testing or Selenium.)
    """
    # Set up a minimal Flask app for simulation:
    app = Flask(__name__)
    app.secret_key = os.urandom(24)
    
    # Dummy endpoints to simulate processing:
    @app.route('/simulate_flow', methods=['GET'])
    def simulate_flow():
        # Simulate a fixed flow delay (e.g., 300ms for OTP, 400ms for hash, plus network latency)
        time.sleep(0.3)
        time.sleep(0.4)
        return "Flow Complete", 200

    with app.test_client() as client:
        durations = []
        for _ in range(trials):
            start = time.perf_counter()
            response = client.get('/simulate_flow')
            end = time.perf_counter()
            durations.append((end - start) * 1000)  # in milliseconds
        avg_duration = np.mean(durations)
        return durations, avg_duration

def plot_usability_flow():
    durations, avg_duration = simulate_usability_flow()
    trials = np.arange(1, len(durations) + 1)
    plt.figure(figsize=(12, 8))
    plt.plot(trials, durations, marker='s', linestyle='-', color='orange', label=f'Flow Duration (avg: {avg_duration:.2f} ms)')
    plt.title('Simulated End-to-End Usability Flow Duration')
    plt.xlabel('Trial')
    plt.ylabel('Duration (ms)')
    plt.legend(fontsize=14)
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, 'usability_flow.png'), dpi=300, bbox_inches='tight')
    plt.close()

# ------------------------------------------------------------------------------------------------
# Run All Evaluations and Generate Visualizations
# ------------------------------------------------------------------------------------------------
def run_all_evaluations():
    print("Plotting Encryption/Decryption Overhead...")
    plot_encryption_decryption_overhead()
    print("Plotting Authentication Latency...")
    plot_authentication_latency()
    print("Plotting Scalability Metrics...")
    plot_scalability()
    print("Plotting Brute Force OTP Simulation...")
    plot_brute_force_otp()
    print("Plotting Usability Flow Duration...")
    plot_usability_flow()

if __name__ == '__main__':
    run_all_evaluations()
    print("All evaluation plots generated in the output directory.")
