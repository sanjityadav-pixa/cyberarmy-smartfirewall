import requests
import time
import sys

# Target Firewall (Port 8080)
TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"

def test_legit():
    print("\n[+] 1. Testing Normal Legitimate Traffic...")
    try:
        res = requests.get(f"{TARGET}/")
        print(f"Status Code: {res.status_code}")
        print(f"Response: {res.text}")
    except Exception as e:
        print(f"Error: {e}")

def test_sqli():
    print("\n[!] 2. Launching SQL Injection Attack...")
    try:
        res = requests.get(f"{TARGET}/api/user?id=1' OR '1'='1")
        print(f"Status Code: {res.status_code}")
        print(f"Firewall Block Response: {res.text}")
    except Exception as e:
        print(f"Error: {e}")

def test_xss():
    print("\n[!] 3. Launching Cross-Site Scripting (XSS) Attack...")
    try:
        res = requests.get(f"{TARGET}/api/user?id=<script>alert('hacked')</script>")
        print(f"Status Code: {res.status_code}")
        print(f"Firewall Block Response: {res.text}")
    except Exception as e:
        print(f"Error: {e}")

def test_flood():
    print("\n[!] 4. Launching DoS Rate-Limit Burst (20 requests)...")
    for i in range(20):
        try:
            res = requests.get(f"{TARGET}/")
            print(f"Request #{i+1}: Status {res.status_code}")
            time.sleep(0.05)
        except Exception as e:
            print(f"Request #{i+1} Failed: {e}")

if __name__ == "__main__":
    print(f"Targeting: {TARGET}")
    test_legit()
    time.sleep(1)
    test_sqli()
    time.sleep(1)
    test_xss()
    time.sleep(1)
    test_flood()