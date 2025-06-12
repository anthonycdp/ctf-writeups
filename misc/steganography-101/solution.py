#!/usr/bin/env python3
"""
Steganography 101 - Solution Script
Extracts hidden flags from images using various steganography techniques
"""

import os
import sys

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("[!] Pillow not installed. Install with: pip install pillow")

LENGTH_PREFIX_BYTES = 4
MAX_MESSAGE_LENGTH = 10000


def bits_to_bytes(bit_list: list) -> bytes:
    """Convert a list of bits to bytes."""
    result = []
    for i in range(0, len(bit_list), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bit_list):
                byte = (byte << 1) | bit_list[i + j]
        result.append(byte)
    return bytes(result)


def extract_lsb(image_path: str) -> str | None:
    """
    Extract data hidden in LSB of RGB channels.
    Expects: 32-bit length prefix followed by data.
    """
    if not PIL_AVAILABLE:
        print("[-] Pillow required for LSB extraction")
        return None

    try:
        img = Image.open(image_path)
        pixels = list(img.getdata())

        bits = []
        for pixel in pixels:
            r, g, b = pixel[:3]
            bits.extend([r & 1, g & 1, b & 1])

        data = bits_to_bytes(bits)
        length = int.from_bytes(data[:LENGTH_PREFIX_BYTES], 'big')
        print(f"[*] LSB extracted length: {length} bytes")

        if 0 < length < MAX_MESSAGE_LENGTH:
            return data[LENGTH_PREFIX_BYTES:LENGTH_PREFIX_BYTES + length].decode(
                'utf-8', errors='ignore'
            )

        return None

    except (OSError, ValueError) as e:
        print(f"[-] LSB extraction error: {e}")
        return None


PRINTABLE_ASCII_MIN = 32
PRINTABLE_ASCII_MAX = 126


def extract_bit_plane(image_path: str, bit_position: int = 1) -> str | None:
    """Extract data from a specific bit plane of the red channel."""
    if not PIL_AVAILABLE:
        print("[-] Pillow required for bit plane extraction")
        return None

    try:
        img = Image.open(image_path)
        pixels = list(img.getdata())

        bits = [(pixel[0] >> bit_position) & 1 for pixel in pixels]

        chars = []
        for i in range(0, len(bits), 8):
            if i + 8 > len(bits):
                break
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            if PRINTABLE_ASCII_MIN <= byte <= PRINTABLE_ASCII_MAX:
                chars.append(chr(byte))
            elif byte == 0:
                break

        return ''.join(chars) if chars else None

    except (OSError, ValueError) as e:
        print(f"[-] Bit plane extraction error: {e}")
        return None


def extract_appended_data(image_path: str) -> str | None:
    """Extract data appended after the PNG IEND chunk."""
    try:
        with open(image_path, 'rb') as f:
            data = f.read()

        iend_pos = data.find(b'IEND')
        if iend_pos == -1:
            return None

        after_image = data[iend_pos + 8:]  # IEND + 4 bytes CRC
        if after_image:
            return after_image.decode('utf-8', errors='ignore').strip()

        return None

    except OSError as e:
        print(f"[-] Appended data extraction error: {e}")
        return None


def extract_metadata(image_path: str) -> dict:
    """Extract metadata from image file."""
    if not PIL_AVAILABLE:
        print("[-] Pillow required for metadata extraction")
        return {}

    try:
        img = Image.open(image_path)
        metadata = {
            'format': img.format,
            'size': img.size,
            'mode': img.mode,
        }

        if hasattr(img, 'info'):
            metadata['info'] = img.info

        if hasattr(img, '_getexif'):
            exif = img._getexif()
            if exif:
                metadata['exif'] = exif

        return metadata

    except (OSError, AttributeError) as e:
        print(f"[-] Metadata extraction error: {e}")
        return {}


PALETTE_MAX_CHARS = 100


def extract_palette_indices(image_path: str) -> str | None:
    """Extract data from palette mode pixel values interpreted as ASCII."""
    if not PIL_AVAILABLE:
        print("[-] Pillow required for palette extraction")
        return None

    try:
        img = Image.open(image_path)

        if img.mode != 'P':
            print(f"[*] Image is not palette mode: {img.mode}")
            return None

        pixels = list(img.getdata())

        chars = []
        for pixel_val in pixels:
            if PRINTABLE_ASCII_MIN <= pixel_val <= PRINTABLE_ASCII_MAX:
                chars.append(chr(pixel_val))
            elif pixel_val == 0 or len(chars) > PALETTE_MAX_CHARS:
                break

        return ''.join(chars) if chars else None

    except (OSError, ValueError) as e:
        print(f"[-] Palette extraction error: {e}")
        return None


def analyze_image(image_path):
    """
    Comprehensive image analysis
    """
    if not os.path.exists(image_path):
        print(f"[-] Image not found: {image_path}")
        return

    print(f"\n[*] Analyzing: {image_path}")
    print("=" * 60)

    # Metadata
    print("\n[1] Metadata Analysis:")
    metadata = extract_metadata(image_path)
    for key, value in metadata.items():
        if key == 'info' and isinstance(value, dict):
            for k, v in value.items():
                print(f"    {k}: {v}")
        else:
            print(f"    {key}: {value}")

    # LSB extraction
    print("\n[2] LSB Extraction:")
    lsb_data = extract_lsb(image_path)
    if lsb_data:
        print(f"    Found: {lsb_data}")
    else:
        print("    No data found in LSB")

    # Bit plane analysis
    print("\n[3] Bit Plane Analysis (bit 1):")
    bit_plane = extract_bit_plane(image_path, bit_position=1)
    if bit_plane:
        # Look for flag pattern
        if 'CTF{' in bit_plane:
            start = bit_plane.find('CTF{')
            end = bit_plane.find('}', start) + 1
            flag = bit_plane[start:end]
            print(f"    Found: {flag}")
        else:
            print(f"    Found text: {bit_plane[:50]}...")
    else:
        print("    No readable data in bit plane 1")

    # Appended data
    print("\n[4] Appended Data:")
    appended = extract_appended_data(image_path)
    if appended:
        print(f"    Found: {appended[:200]}")
    else:
        print("    No appended data found")

    # Palette analysis
    print("\n[5] Palette Analysis:")
    palette_data = extract_palette_indices(image_path)
    if palette_data:
        print(f"    Found: {palette_data}")
    else:
        print("    No palette data or not applicable")


def main():
    print("=" * 60)
    print("Steganography 101 - Solution Script")
    print("=" * 60)

    # Check for challenge images
    challenge_dirs = [
        'challenge/challenges',
        'challenges',
        'challenge'
    ]

    image_files = []

    # Find challenge images
    for d in challenge_dirs:
        if os.path.exists(d):
            for f in os.listdir(d):
                if f.endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                    image_files.append(os.path.join(d, f))

    # If no images found, try to create them
    if not image_files:
        print("\n[*] No challenge images found. Creating them...")
        create_script = 'challenge/create_stego.py'

        if os.path.exists(create_script):
            import subprocess
            subprocess.run(['python3', create_script], cwd='.')

            # Try to find images again
            for d in challenge_dirs:
                if os.path.exists(d):
                    for f in os.listdir(d):
                        if f.endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                            image_files.append(os.path.join(d, f))

    if image_files:
        print(f"\n[*] Found {len(image_files)} challenge images")

        for img_path in sorted(image_files):
            analyze_image(img_path)
    else:
        print("[!] No challenge images found")
        print("[*] Run 'make generate' to create challenge artifacts")

    # Summary
    print("\n" + "=" * 60)
    print("EXPECTED FLAGS:")
    print("=" * 60)
    print("  challenge1.png (LSB):    CTF{lsb_st3g4n0gr4phy_b4s1cs}")
    print("  challenge2.png (Bit 1):  CTF{b1t_pl4n3_4n4lys1s}")
    print("  challenge3.png (Append): CTF{f1l3_4pp3nd3d_d4t4}")
    print("  challenge4.png (Meta):   CTF{m3t4d4t4_1s_1mp0rt4nt}")
    print("  challenge5.png (Palette):CTF{p4l3tt3_0rd3r}")
    print("=" * 60)

    # Tool recommendations
    print("""
[*] Additional tools for steganography:
    - steghide: steghide extract -sf image.jpg
    - zsteg: zsteg image.png
    - binwalk: binwalk image.png
    - exiftool: exiftool image.png
    - strings: strings image.png

[*] Manual analysis tips:
    - Check file size vs visual content
    - Look for unusual color patterns
    - Examine bit planes individually
    - Check for data after image markers
    - Review all metadata fields
""")


if __name__ == '__main__':
    main()
