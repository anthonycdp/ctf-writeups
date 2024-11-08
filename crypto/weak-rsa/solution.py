#!/usr/bin/env python3
"""
Weak RSA - Wiener's Attack Solution
"""
import json
import math

def continued_fraction(num, denom):
    """Compute continued fraction representation"""
    cf = []
    while denom:
        q = num // denom
        cf.append(q)
        num, denom = denom, num - q * denom
    return cf

def convergents(cf):
    """Generate convergents from continued fraction"""
    n_prev, n_curr = 0, 1
    d_prev, d_curr = 1, 0

    for a in cf:
        n_next = a * n_curr + n_prev
        d_next = a * d_curr + d_prev
        yield n_next, d_next
        n_prev, n_curr = n_curr, n_next
        d_prev, d_curr = d_curr, d_next

def wiener_attack(e, n):
    """
    Perform Wiener's attack to recover small d.
    Works when d < n^(1/4) / 3
    """
    cf = continued_fraction(e, n)
    convergents_gen = convergents(cf)

    for k, d in convergents_gen:
        if k == 0:
            continue

        # e*d = k*φ(n) + 1
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # p + q = n - φ(n) + 1
        s = n - phi + 1

        # Discriminant of x² - s*x + n = 0
        discriminant = s * s - 4 * n

        if discriminant < 0:
            continue

        sqrt_disc = math.isqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue

        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2

        if p * q == n:
            return d, p, q

    return None, None, None

def main():
    print("=" * 60)
    print("Weak RSA - Wiener's Attack Solution")
    print("=" * 60)

    try:
        with open('challenge/challenge.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("[-] challenge.json not found")
        print("[*] Run: python challenge/setup.py to generate it")
        return

    n = int(data['n'], 16) if isinstance(data['n'], str) else data['n']
    e = int(data['e'], 16) if isinstance(data['e'], str) else data['e']
    c = int(data['ciphertext'], 16) if isinstance(data['ciphertext'], str) else data['ciphertext']

    print(f"\n[*] n bits: {n.bit_length()}")
    print(f"[*] e bits: {e.bit_length()}")
    print(f"[*] e/n ratio: {e/n:.4f}")

    if e > n:
        print("\n[+] e > n suggests small d - Wiener's attack viable!")

    print("\n[*] Running Wiener's attack...")
    d, p, q = wiener_attack(e, n)

    if d:
        print(f"\n[+] Found private key d!")
        print(f"    d bits: {d.bit_length()}")

        # Decrypt
        m = pow(c, d, n)
        plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big')

        print(f"\n[+] Decrypted: {plaintext}")

        if b'CTF{' in plaintext:
            print(f"\n[+] FLAG FOUND!")
    else:
        print("\n[-] Wiener's attack failed")
        print("[*] The d might be larger than n^(1/4)/3")

if __name__ == '__main__':
    main()
