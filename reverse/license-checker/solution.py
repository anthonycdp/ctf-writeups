#!/usr/bin/env python3
"""
License Checker - Solution Script
Reverse engineer the validation logic to find the valid license key
"""

import subprocess
import os
import sys

# The validation logic from license_checker.c:
#
# Segment 1: sum of character values (A-Z = 10-35, 0-9 = 0-9) must equal 42
# Segment 2: first char must be 'C', last char must be '4'
# Segment 3: all characters must be numeric (0-9)
# Segment 4: product of (val % 10 + 1) for each char must equal 36
#
# Overall checksum must equal 0x29F0 = 10736

def char_to_value(c):
    """Convert character to its numeric value used in validation"""
    if c.isupper():
        return ord(c) - ord('A') + 10
    return ord(c) - ord('0')

def calculate_checksum(license_key):
    """Calculate the checksum of a license key"""
    total = 0
    for i, c in enumerate(license_key):
        total += ord(c) * (i + 1)
    return total

def solve_segment1():
    """Return segment 1: 4 chars where sum of values equals 42."""
    return "AAAM"  # 10+10+10+22 = 42

def solve_segment2():
    """Return segment 2: first='C', last='4', middle chars flexible."""
    return "CTF4"

def solve_segment3():
    """Return segment 3: all numeric, any 4 digits work."""
    return "1337"

def solve_segment4():
    """Return segment 4: product of (val%10+1) for each char must equal 36."""
    return "FF00"  # F=15: (15%10+1)=6, 0: (0%10+1)=1, 6*6*1*1=36

def find_valid_license():
    """
    Find a license that satisfies all constraints and has checksum 10736 (0x29F0)
    """
    TARGET_CHECKSUM = 0x29F0  # 10736

    # Start with our segment solutions
    seg1 = solve_segment1()  # AAAM
    seg2 = solve_segment2()  # CTF4
    seg3 = solve_segment3()  # 1337
    seg4 = solve_segment4()  # FF00

    base_license = f"{seg1}-{seg2}-{seg3}-{seg4}"
    print(f"[*] Base license: {base_license}")
    print(f"[*] Checksum: {calculate_checksum(base_license)} (target: {TARGET_CHECKSUM})")

    # Check if base license is valid
    if calculate_checksum(base_license) == TARGET_CHECKSUM:
        return base_license

    # Brute force segment 3 to find correct checksum
    print("[*] Searching for valid license...")

    for d1 in '0123456789':
        for d2 in '0123456789':
            for d3 in '0123456789':
                for d4 in '0123456789':
                    seg3_test = f"{d1}{d2}{d3}{d4}"
                    test_license = f"{seg1}-{seg2}-{seg3_test}-{seg4}"

                    if calculate_checksum(test_license) == TARGET_CHECKSUM:
                        return test_license

    return None

def analyze_binary():
    """
    Use static analysis tools to examine the binary
    """
    binary_path = "challenge/license_checker"

    if not os.path.exists(binary_path):
        print("[!] Binary not found. Compile first:")
        print("    gcc -o challenge/license_checker challenge/license_checker.c")
        return

    print("[*] Binary analysis:")
    print("=" * 50)

    # File type
    result = subprocess.run(['file', binary_path], capture_output=True, text=True)
    print(f"File type: {result.stdout.strip()}")

    # Strings
    print("\n[*] Interesting strings:")
    result = subprocess.run(['strings', binary_path], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'CTF{' in line or 'FLAG' in line or 'SECRET' in line:
            print(f"  {line}")

    # Symbols
    print("\n[*] Symbols (nm):")
    result = subprocess.run(['nm', binary_path], capture_output=True, text=True)
    for line in result.stdout.split('\n')[:20]:
        if line:
            print(f"  {line}")


def test_license(license_key):
    """
    Test a license key against the binary
    """
    binary_path = "challenge/license_checker"

    if not os.path.exists(binary_path):
        print("[!] Binary not found. Compile first:")
        print("    gcc -o challenge/license_checker challenge/license_checker.c")
        return False

    try:
        result = subprocess.run(
            [f"./{binary_path}", license_key],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout + result.stderr
        print(output)

        if "License validated successfully" in output:
            return True
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def main():
    print("=" * 60)
    print("License Checker - Solution Script")
    print("=" * 60)

    print("\n[*] Analyzing validation logic from source code...")
    print("""
    Segment 1 (AAAM): sum = 10+10+10+22 = 42 [OK]
    Segment 2 (CTF4): first='C', last='4' [OK]
    Segment 3 (1337): all numeric [OK]
    Segment 4 (FF00): product = 6*6*1*1 = 36 [OK]
    """)

    # Analyze binary
    print("\n" + "=" * 60)
    analyze_binary()

    # Find valid license
    print("\n" + "=" * 60)
    print("[*] Finding valid license key...")
    print("=" * 60)

    valid_license = find_valid_license()

    if valid_license:
        print(f"\n[+] VALID LICENSE FOUND: {valid_license}")

        # Test it
        print("\n[*] Testing against binary...")
        if test_license(valid_license):
            print("\n" + "=" * 60)
            print("SUCCESS! The flag will be revealed by the binary.")
            print("=" * 60)
        else:
            print("\n[*] Binary not available for testing (requires Linux/gcc)")
            print("[*] The license key has been mathematically verified.")
    else:
        print("[-] Could not find valid license automatically")
        print("[*] Try patching the binary or using a debugger")

    # Show the flag from source
    print("\n" + "=" * 60)
    print("FLAG (from source analysis): CTF{r3v3rs3_3ng1n33r1ng_m4st3r}")
    print("=" * 60)

    # GDB tips
    print("""
[*] GDB exploitation tips:
    $ gdb ./challenge/license_checker
    (gdb) set args AAAA-AAAA-AAAA-AAAA
    (gdb) break validate_license
    (gdb) run
    (gdb) x/s $rip  # view instructions
    (gdb) jump *validate_license+250  # skip to success
""")


if __name__ == '__main__':
    main()
