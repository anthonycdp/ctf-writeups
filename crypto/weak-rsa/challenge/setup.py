#!/usr/bin/env python3
"""
Weak RSA Challenge Generator
Creates an RSA challenge with a small private exponent
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json

def generate_weak_rsa():
    """
    Generate RSA keys with a small private exponent.
    This makes the key vulnerable to Wiener's attack.
    """
    from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

    # Generate two primes
    p = getPrime(1024)
    q = getPrime(1024)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Use small public exponent
    e = 65537

    # Calculate private exponent (normally this would be large)
    d = inverse(e, phi)

    # The vulnerability: we'll use a small d (for Wiener's attack demo)
    # In reality, this would require specific key generation
    # For this challenge, we'll make d small by using a large e

    # For the actual challenge, we'll use small primes that are close together
    # This makes Fermat factorization possible

    return n, e, d, p, q

def generate_fermat_vulnerable_rsa():
    """Generate RSA with primes close together (vulnerable to Fermat factorization)"""
    from Crypto.Util.number import getPrime, inverse, bytes_to_long

    # Generate a prime near a specific value
    # p and q will be close together
    base = 2 ** 512
    p = getPrime(512)
    # q is very close to p
    q = p + 2  # This is intentionally weak!

    # Ensure q is prime
    from Crypto.Util.number import isPrime
    while not isPrime(q):
        q += 2

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)

    return n, e, d, p, q

def generate_small_primes_rsa():
    """Generate RSA with small primes (easy to factor)"""
    from Crypto.Util.number import getPrime, inverse, bytes_to_long

    # Intentionally small primes for the challenge
    p = getPrime(256)  # Much smaller than secure RSA
    q = getPrime(256)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)

    return n, e, d, p, q

def generate_wiener_vulnerable_rsa():
    """
    Generate RSA vulnerable to Wiener's attack.
    When d < n^0.25 / 3, the private key can be recovered.
    """
    from Crypto.Util.number import getPrime, inverse

    # Use larger primes but with specific properties
    # We need d to be small, which happens when e is large

    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose a large e such that d is small
    # d will be approximately n/e in size
    # For Wiener's attack to work: d < n^(1/4) / 3

    import math
    max_d = int(n ** 0.25) // 3

    # We need e such that e*d ≡ 1 (mod phi)
    # Choose a small d first, then compute e
    d = getPrime(200)  # Small d
    while d >= max_d:
        d = getPrime(200)

    # e = d^(-1) mod phi
    e = inverse(d, phi)

    return n, e, d, p, q

if __name__ == '__main__':
    from Crypto.Util.number import bytes_to_long, long_to_bytes

    # Generate weak RSA keys
    n, e, d, p, q = generate_wiener_vulnerable_rsa()

    # The flag
    flag = b"CTF{w13n3r_4tt4ck_sm4ll_d_1s_d4ng3r0u5}"
    m = bytes_to_long(flag)

    # Encrypt the flag
    c = pow(m, e, n)

    # Save public key and ciphertext
    challenge = {
        "n": hex(n),
        "e": e,
        "ciphertext": hex(c)
    }

    with open('challenge.json', 'w') as f:
        json.dump(challenge, f, indent=2)

    # Save solution (not included in challenge files!)
    solution = {
        "p": hex(p),
        "q": hex(q),
        "d": hex(d),
        "flag": flag.decode()
    }

    with open('solution.json', 'w') as f:
        json.dump(solution, f, indent=2)

    print("[+] Challenge generated!")
    print(f"[*] n bits: {n.bit_length()}")
    print(f"[*] e: {e}")
    print(f"[*] d bits: {d.bit_length()}")
    print(f"[*] Saved to challenge.json")
