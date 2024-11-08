# Weak RSA - Write-up

**Category:** Cryptography
**Difficulty:** Medium
**Flag:** `CTF{w13n3r_4tt4ck_sm4ll_d_1s_d4ng3r0u5}`

## Challenge Description

Our target has implemented "enhanced" RSA with an unusually large public exponent. The challenge provides:
- `n` - the modulus (1024 bits)
- `e` - the public exponent (suspiciously large!)
- `c` - the ciphertext

> "Our security expert said using a HUGE public exponent would make RSA unbreakable."

## Initial Analysis

### Understanding RSA Basics

In RSA encryption:
- `n = p * q` (product of two primes)
- `φ(n) = (p-1)(q-1)` (Euler's totient)
- `e * d ≡ 1 (mod φ(n))` (key relationship)
- `c = m^e mod n` (encryption)
- `m = c^d mod n` (decryption)

### Observing the Anomaly

Looking at the public exponent `e`, it's unusually large - approximately the same size as `n`. In standard RSA:
- `e` is typically 65537 (small)
- `d` is approximately the same size as `n`

But since `e * d ≡ 1 (mod φ(n))`:
- If `e` is large, `d` must be small!

## Attack Strategy: Wiener's Attack

### Theoretical Background

Wiener's attack works when the private exponent `d` is small. Specifically, if:

```
d < n^(1/4) / 3
```

Then `d` can be efficiently recovered using continued fractions.

### Why Does This Work?

The relationship `e * d ≡ 1 (mod φ(n))` can be written as:

```
e * d = k * φ(n) + 1
```

This gives us:
```
k/d ≈ e/φ(n) ≈ e/n
```

The continued fraction expansion of `e/n` will contain convergents `k/d` that reveal the private key!

## Implementation

### Step 1: Continued Fraction Expansion

```python
def continued_fraction(n, d):
    """Generate continued fraction expansion of n/d"""
    cf = []
    while d:
        q = n // d
        cf.append(q)
        n, d = d, n % d
    return cf

def convergents(cf):
    """Generate convergents from continued fraction"""
    n0, n1 = 0, 1
    d0, d1 = 1, 0

    for a in cf:
        n2 = a * n1 + n0
        d2 = a * d1 + d0
        yield n2, d2
        n0, n1 = n1, n2
        d0, d1 = d1, d2
```

### Step 2: Wiener's Attack Implementation

```python
from Crypto.Util.number import long_to_bytes

def wiener_attack(e, n):
    """
    Wiener's attack on RSA with small d.
    Returns d if found, None otherwise.
    """
    cf = continued_fraction(e, n)

    for k, d in convergents(cf):
        if k == 0:
            continue

        # Check if d is valid
        # e*d - 1 should be divisible by k
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # φ(n) = n - p - q + 1
        # So p + q = n - φ(n) + 1
        s = n - phi + 1

        # Check if p and q are valid
        # p and q are roots of x² - s*x + n = 0
        discriminant = s * s - 4 * n

        if discriminant < 0:
            continue

        import math
        sqrt_disc = math.isqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue

        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2

        if p * q == n:
            return d, p, q

    return None, None, None
```

### Step 3: Decrypting the Message

```python
def solve():
    import json

    # Load challenge data
    with open('challenge.json', 'r') as f:
        data = json.load(f)

    n = int(data['n'], 16)
    e = int(data['e'], 16)
    c = int(data['ciphertext'], 16)

    print(f"[*] n = {n}")
    print(f"[*] e = {e}")
    print(f"[*] c = {c}")
    print(f"[*] e bit length: {e.bit_length()}")
    print(f"[*] n bit length: {n.bit_length()}")

    # Wiener's attack
    print("\n[+] Running Wiener's attack...")
    d, p, q = wiener_attack(e, n)

    if d:
        print(f"[+] Found d = {d}")
        print(f"[+] d bit length: {d.bit_length()}")

        # Decrypt
        m = pow(c, d, n)
        flag = long_to_bytes(m)
        print(f"\n[+] Decrypted message: {flag}")
        return flag
    else:
        print("[-] Wiener's attack failed")
        return None

if __name__ == '__main__':
    solve()
```

## Complete Solution Script

```python
#!/usr/bin/env python3
"""
Weak RSA Challenge - Wiener's Attack Solution
"""
import json
import math
from Crypto.Util.number import long_to_bytes

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
        # φ(n) = (e*d - 1) / k
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # n = p*q and φ(n) = (p-1)(q-1)
        # So: p + q = n - φ(n) + 1
        s = n - phi + 1

        # p and q are roots of: x² - s*x + n = 0
        discriminant = s * s - 4 * n

        if discriminant < 0:
            continue

        sqrt_disc = math.isqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue

        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2

        if p * q == n:
            print(f"[+] Found valid factorization!")
            print(f"    p = {p}")
            print(f"    q = {q}")
            return d, p, q

    return None, None, None

def main():
    print("=" * 60)
    print("Weak RSA Challenge - Wiener's Attack")
    print("=" * 60)

    # Load challenge
    with open('challenge/challenge.json', 'r') as f:
        data = json.load(f)

    n = int(data['n'], 16)
    e = int(data['e'], 16)
    c = int(data['ciphertext'], 16)

    print(f"\n[*] Challenge parameters:")
    print(f"    n bits: {n.bit_length()}")
    print(f"    e bits: {e.bit_length()}")
    print(f"    e/n ratio: {e/n:.4f}")

    # The hint suggests e is unusually large
    # This means d must be small -> Wiener's attack!

    print("\n[+] Running Wiener's attack...")
    d, p, q = wiener_attack(e, n)

    if d is None:
        print("[-] Attack failed!")
        return

    print(f"\n[+] Private exponent d found!")
    print(f"    d bits: {d.bit_length()}")
    print(f"    d < n^(1/4)/3 check: {d < (n ** 0.25) / 3}")

    # Decrypt the ciphertext
    m = pow(c, d, n)
    plaintext = long_to_bytes(m)

    print(f"\n[+] Decrypted plaintext:")
    print(f"    {plaintext}")

    if b'CTF{' in plaintext:
        print(f"\n[+] FLAG CAPTURED!")

if __name__ == '__main__':
    main()
```

## Alternative: Using Existing Tools

### RsaCtfTool

```bash
# Clone and run RsaCtfTool
python3 RsaCtfTool.py -n <n_value> -e <e_value> --uncipher <c_value>
```

### SageMath Implementation

```python
# In SageMath
n = <n_value>
e = <e_value>
c = <c_value>

# Use the built-in Wiener attack
from sage.crypto.attacks.rsa import wiener
d = wiener(e, n)

if d:
    m = power_mod(c, d, n)
    print(m.hex())
```

## Key Takeaways

### Why This Attack Works

1. **RSA Relationship**: `e * d ≡ 1 (mod φ(n))` means if `e` is large, `d` must be small
2. **Continued Fractions**: The ratio `e/n` approximates `k/d`, revealing `d`
3. **Efficiency**: Wiener's attack is polynomial time when `d` is small

### Mathematical Constraint

For Wiener's attack to work:
```
d < n^(1/4) / 3
```

This translates to approximately `d < 2^256` for a 1024-bit `n`.

### Prevention

1. **Standard e values**: Use `e = 65537` (common and secure)
2. **Key validation**: Ensure `d` is not unusually small
3. **Proper key generation**: Follow RSA key generation standards

## Attack Summary

| Step | Action | Result |
|------|--------|--------|
| 1 | Analyze e | Unusually large public exponent |
| 2 | Hypothesis | Small d vulnerability |
| 3 | Wiener's attack | Continued fraction expansion |
| 4 | Find convergents | Test k/d pairs |
| 5 | Validate | Check if p*q = n |
| 6 | Decrypt | m = c^d mod n |

## References

- Wiener, M. (1990). "Cryptanalysis of Short RSA Secret Exponents"
- Boneh, D. (1999). "Twenty Years of Attacks on the RSA Cryptosystem"

---

*This challenge demonstrates why cryptographic parameters must be chosen carefully, following established standards rather than "intuition" about what seems more secure.*
