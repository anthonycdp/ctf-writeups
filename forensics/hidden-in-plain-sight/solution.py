#!/usr/bin/env python3
"""
Hidden in Plain Sight - Solution Script
"""
import os
import re
import subprocess
from PIL import Image

FLAG_PATTERN = re.compile(r'CTF\{[^}]+\}')
LENGTH_PREFIX_BITS = 16


def bits_to_bytes(bits: list) -> bytes:
    """Convert a list of bits to bytes."""
    result = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) == 8:
            result.append(int(''.join(map(str, byte_bits)), 2))
    return bytes(result)


def extract_flag(text: str) -> str | None:
    """Extract CTF flag from text."""
    match = FLAG_PATTERN.search(text)
    return match.group() if match else None


def solve_lsb(image_path: str) -> str | None:
    """Extract LSB steganography from PNG."""
    print(f"[*] Extracting LSB from {image_path}...")

    try:
        img = Image.open(image_path)
        pixels = img.load()
        width, height = img.size

        bits = []
        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]
                bits.append(r & 1)

        length = int(''.join(map(str, bits[:LENGTH_PREFIX_BITS])), 2)
        data_bits = bits[LENGTH_PREFIX_BITS:LENGTH_PREFIX_BITS + length * 8]
        hidden = bits_to_bytes(data_bits).decode('utf-8', errors='ignore')

        flag = extract_flag(hidden)
        if flag:
            print(f"[+] FLAG: {flag}")
            return flag

    except FileNotFoundError:
        print(f"[-] File not found: {image_path}")
        print("[*] Run: python challenge/create_challenge.py to generate it")
    except OSError as e:
        print(f"[-] Error reading image: {e}")

    return None

def solve_zip(zip_path: str) -> None:
    """Extract hidden files from ZIP."""
    print(f"\n[*] Extracting from ZIP: {zip_path}...")

    if not os.path.exists(zip_path):
        print(f"[-] File not found: {zip_path}")
        return

    extract_dir = 'extracted'
    os.makedirs(extract_dir, exist_ok=True)

    subprocess.run(
        ['unzip', '-o', zip_path, '-d', extract_dir],
        capture_output=True,
        check=False
    )

    for filename in os.listdir(extract_dir):
        if filename.startswith('.'):
            filepath = os.path.join(extract_dir, filename)
            with open(filepath, 'r', encoding='utf-8') as file:
                content = file.read()
                print(f"[+] Found hidden file: {filename}")
                print(f"[+] FLAG: {content.strip()}")

def solve_polyglot(filepath: str) -> None:
    """Extract hidden data from polyglot file."""
    print(f"\n[*] Analyzing polyglot: {filepath}...")

    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        return

    with open(filepath, 'rb') as f:
        data = f.read()

    iend_pos = data.find(b'IEND')
    if iend_pos == -1:
        return

    # Data after IEND + CRC (12 bytes: IEND(4) + CRC(4) + padding)
    hidden = data[iend_pos + 12:]
    if hidden:
        print("[+] Found data after PNG end marker")
        text = hidden.decode('utf-8', errors='ignore')
        flag = extract_flag(text)
        if flag:
            print(f"[+] FLAG: {flag}")

def main():
    print("=" * 60)
    print("Hidden in Plain Sight - Solutions")
    print("=" * 60)

    # These require running create_challenge.py first
    base = 'challenge'

    # LSB Steganography
    solve_lsb(f'{base}/hidden.png')

    # ZIP with hidden file
    solve_zip(f'{base}/secret.zip')

    # Polyglot file
    solve_polyglot(f'{base}/polyglot.png')

    print("\n" + "=" * 60)
    print("To generate challenge files:")
    print("  python challenge/create_challenge.py")
    print("=" * 60)

if __name__ == '__main__':
    main()
