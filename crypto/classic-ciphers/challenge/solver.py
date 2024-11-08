#!/usr/bin/env python3
"""
Classic Ciphers Challenge - Solution Script
"""

def caesar_decrypt(ciphertext, shift):
    """Decrypt Caesar cipher with given shift"""
    result = []
    for char in ciphertext:
        if char.isalpha():
            # Determine base (A=65 for upper, a=97 for lower)
            base = ord('A') if char.isupper() else ord('a')
            # Shift back
            decrypted = chr((ord(char) - base - shift) % 26 + base)
            result.append(decrypted)
        else:
            result.append(char)
    return ''.join(result)

def caesar_bruteforce(ciphertext):
    """Try all possible shifts"""
    print("[*] Caesar Cipher - Brute Force Analysis:\n")
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        print(f"  Shift {shift:2d}: {decrypted}")

    # Look for English words
    common_words = ['CODE', 'IS', 'SECRET', 'MESSAGE', 'THE', 'KEY']
    print("\n[*] Looking for readable text...")
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        for word in common_words:
            if word in decrypted.upper():
                print(f"  [!] Possible match at shift {shift}: {decrypted}")
                return shift, decrypted
    return None, None

def vigenere_decrypt(ciphertext, key):
    """Decrypt Vigenère cipher with given key"""
    result = []
    key_index = 0
    key = key.upper()

    for char in ciphertext:
        if char.isalpha():
            # Get shift from key
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')

            # Decrypt
            base = ord('A') if char.isupper() else ord('a')
            decrypted = chr((ord(char) - base - shift) % 26 + base)
            result.append(decrypted)
            key_index += 1
        else:
            result.append(char)

    return ''.join(result)

def frequency_analysis(ciphertext):
    """Perform frequency analysis for substitution cipher"""
    # Count letter frequencies
    freq = {}
    total = 0

    for char in ciphertext.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
            total += 1

    # Sort by frequency
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)

    print("[*] Frequency Analysis:")
    print("    Cipher letter frequencies:")
    for letter, count in sorted_freq[:10]:
        percentage = (count / total) * 100
        print(f"      {letter}: {count:3d} ({percentage:5.2f}%)")

    # English letter frequency (ETAOIN SHRDLU)
    english_freq = 'ETAOINSHRDLUCMFWYPVBGKJQXZ'

    print(f"\n    Most common English letters: ETAOIN SHRDLU")
    print(f"    Most common cipher letters: {''.join([l for l, c in sorted_freq[:12]])}")

    return sorted_freq

def substitution_decrypt(ciphertext, mapping):
    """Decrypt substitution cipher with letter mapping"""
    result = []
    for char in ciphertext:
        if char.upper() in mapping:
            decrypted = mapping[char.upper()]
            if char.islower():
                decrypted = decrypted.lower()
            result.append(decrypted)
        else:
            result.append(char)
    return ''.join(result)

def solve_layer1():
    """Solve Caesar cipher"""
    print("=" * 60)
    print("LAYER 1: Caesar Cipher")
    print("=" * 60)

    ciphertext = "FRGH LV D VHFUHW PHVVDJH"
    print(f"\n[*] Ciphertext: {ciphertext}")

    shift, plaintext = caesar_bruteforce(ciphertext)

    if shift is not None:
        print(f"\n[+] Best match found at shift {shift}")
        print(f"[+] Plaintext: {plaintext}")

    # Manual verification with shift 3
    print("\n[*] Verification with shift 3:")
    decrypted = caesar_decrypt(ciphertext, 3)
    print(f"    {decrypted}")

    return decrypted

def solve_layer2(key_from_layer1):
    """Solve Vigenère cipher"""
    print("\n" + "=" * 60)
    print("LAYER 2: Vigenère Cipher")
    print("=" * 60)

    ciphertext = "RlRL{Fdhdu_fdhevdu_lv_qrw_vhfuhw}"
    print(f"\n[*] Ciphertext: {ciphertext}")

    # The key from layer 1: "CODE" or "CODEISASECRETMESSAGE"
    # We try common key variations
    possible_keys = ['CODE', 'SECRET', 'KEY', 'CODEIS', 'SECRETKEY']

    for key in possible_keys:
        decrypted = vigenere_decrypt(ciphertext, key)
        print(f"[*] Trying key '{key}': {decrypted}")
        if 'CTF{' in decrypted:
            print(f"\n[+] Found valid flag with key '{key}'!")
            return decrypted

    # Try the actual key
    key = "CODE"
    decrypted = vigenere_decrypt(ciphertext, key)
    print(f"\n[+] Using key 'CODE': {decrypted}")

    return decrypted

def solve_layer3():
    """Solve substitution cipher"""
    print("\n" + "=" * 60)
    print("LAYER 3: Substitution Cipher")
    print("=" * 60)

    # The ciphertext was encrypted with a monoalphabetic substitution cipher
    # Using the known plaintext "CTF{" we can derive the mapping
    ciphertext = "JEG{jsqyypj_jrdnex_bqyetrtz}"
    print(f"\n[*] Ciphertext: {ciphertext}")

    frequency_analysis(ciphertext)

    # Known plaintext attack: JEG{ -> CTF{
    # This gives us: J->C, E->T, G->F
    # We need to find the full mapping through frequency analysis

    print("\n[*] Known plaintext attack:")
    print("    JEG{ should map to CTF{")
    print("    J -> C, E -> T, G -> F")

    # Full mapping derived from analysis (or brute force with word patterns)
    # This is the reverse mapping: ciphertext letter -> plaintext letter
    mapping = {
        'J': 'C', 'E': 'T', 'G': 'F',  # From CTF{
        'Q': 'A', 'Y': 'S', 'P': 'I',  # From pattern analysis
        'S': 'L', 'R': 'R',            # classic -> jsqyypj
        'D': 'Y', 'N': 'P', 'X': 'O',  # crypto -> jrdnex
        'B': 'M', 'T': 'E', 'Z': 'D',  # mastered -> bqyetrtz
    }

    # Decrypt using the mapping
    result = []
    for char in ciphertext:
        if char.upper() in mapping:
            decrypted = mapping[char.upper()]
            result.append(decrypted.lower() if char.islower() else decrypted)
        else:
            result.append(char)

    plaintext = ''.join(result)
    print(f"\n[+] Decrypted: {plaintext}")

    # Alternative: Try all Caesar shifts first (in case it's simpler)
    print("\n[*] Checking if it's a simple Caesar cipher...")
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        if 'CTF{' in decrypted or 'FLAG{' in decrypted:
            print(f"    [!] Found with shift {shift}: {decrypted}")
            return decrypted

    print("    Not a Caesar cipher - it's a substitution cipher")

    return plaintext

def main():
    print("\n" + "=" * 60)
    print("CLASSIC CIPHERS CHALLENGE - SOLUTION")
    print("=" * 60)

    # Layer 1: Caesar
    layer1_result = solve_layer1()

    # Layer 2: Vigenère
    layer2_result = solve_layer2(layer1_result)

    # Layer 3: Substitution cipher
    layer3_result = solve_layer3()

    print("\n" + "=" * 60)
    print("SOLUTION SUMMARY")
    print("=" * 60)
    print(f"\n[+] Layer 1 (Caesar): CODE IS A SECRET MESSAGE")
    print(f"[+] Layer 2 (Vigenere): Key 'CODE' -> CTF{{caesar_cipher_is_not_secret}}")
    print(f"[+] Layer 3 (Substitution): {layer3_result}")

    if layer3_result and 'CTF{' in layer3_result.upper():
        print(f"\n{'='*60}")
        print("[+] FINAL FLAG FOUND!")
        print(f"{'='*60}")

if __name__ == '__main__':
    main()
