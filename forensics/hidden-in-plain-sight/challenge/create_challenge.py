#!/usr/bin/env python3
"""
Hidden in Plain Sight - CTF Challenge Creator
This script creates a PNG image with hidden data using various techniques
"""

from PIL import Image
import struct
import io

def create_stego_image():
    """Create an image with hidden flag using LSB steganography"""

    # Create a simple image (200x200 pixels)
    width, height = 200, 200
    img = Image.new('RGB', (width, height), color='white')
    pixels = img.load()

    # Create a pattern
    for x in range(width):
        for y in range(height):
            # Create a gradient pattern
            r = (x + y) % 256
            g = (x * 2) % 256
            b = (y * 2) % 256
            pixels[x, y] = (r, g, b)

    # The flag to hide
    flag = "CTF{h1dd3n_1n_pl41n_s1ght_m3t4d4t4}"

    # Method 1: Hide in LSB (Least Significant Bit) of red channel
    # First, store the length of the flag (2 bytes)
    flag_bytes = flag.encode('utf-8')
    length = len(flag_bytes)

    # Convert length to binary
    length_bits = format(length, '016b')

    # Convert flag to bits
    flag_bits = ''.join(format(byte, '08b') for byte in flag_bytes)

    # Combine: 16 bits for length + flag bits
    all_bits = length_bits + flag_bits

    print(f"[*] Flag length: {length}")
    print(f"[*] Bits to hide: {len(all_bits)}")

    # Embed in LSBs of red channel
    bit_index = 0
    for x in range(width):
        for y in range(height):
            if bit_index >= len(all_bits):
                break

            r, g, b = pixels[x, y]

            # Modify LSB of red channel
            bit = int(all_bits[bit_index])
            r = (r & 0xFE) | bit  # Clear LSB, set to our bit

            pixels[x, y] = (r, g, b)
            bit_index += 1

        if bit_index >= len(all_bits):
            break

    # Save the image
    img.save('hidden.png', 'PNG')
    print(f"[+] Image saved as 'hidden.png'")
    print(f"[*] Hidden {bit_index} bits in image")

    # Method 2: Also add metadata comment
    from PIL import PngImagePlugin
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Author", "Anonymous CTF Player")
    meta.add_text("Software", "Super Secret Editor v1.0")
    meta.add_text("Comment", "Nothing to see here... or is there?")
    img.save('hidden_with_meta.png', 'PNG', pnginfo=meta)
    print(f"[+] Image with metadata saved as 'hidden_with_meta.png'")

def create_zip_with_hidden_file():
    """Create a ZIP file with hidden data"""
    import zipfile
    import io

    # Create a simple text file as a decoy
    decoy_content = b"This is just a regular text file.\nNothing special here!\n"

    # The flag to hide in a hidden file
    flag = b"CTF{z1p_f1l3s_c4n_h1d3_s3cr3ts}\n"

    # Create ZIP in memory
    with zipfile.ZipFile('secret.zip', 'w') as zf:
        # Add decoy file
        zf.writestr('readme.txt', decoy_content)

        # Add "hidden" file (won't show in normal file explorers)
        zf.writestr('.flag', flag)

    print("[+] ZIP file created as 'secret.zip'")

def create_polyglot_file():
    """Create a file that's both valid PNG and ZIP"""
    # This is more advanced - creates a file valid as both PNG and ZIP

    # Start with minimal PNG
    png_header = bytes([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
        0x00, 0x00, 0x00, 0x0D,  # IHDR length
        0x49, 0x48, 0x44, 0x52,  # "IHDR"
        0x00, 0x00, 0x00, 0x01,  # width: 1
        0x00, 0x00, 0x00, 0x01,  # height: 1
        0x08, 0x02,              # bit depth: 8, color type: 2
        0x00, 0x00, 0x00,        # compression, filter, interlace
        0x90, 0x77, 0x53, 0xDE,  # CRC
        0x00, 0x00, 0x00, 0x0C,  # IDAT length
        0x49, 0x44, 0x41, 0x54,  # "IDAT"
        0x08, 0xD7, 0x63, 0xF8,  # Compressed data
        0x0F, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x05,
        0x18, 0xD8, 0x25,        # CRC
        0x00, 0x00, 0x00, 0x00,  # IEND length
        0x49, 0x45, 0x4E, 0x44,  # "IEND"
        0xAE, 0x42, 0x60, 0x82,  # CRC
    ])

    # ZIP with hidden content
    import zipfile
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        zf.writestr('.hidden_flag', 'CTF{p0lygl0t_f1l3_m4st3r}')

    # Combine (ZIP can be appended to PNG)
    with open('polyglot.png', 'wb') as f:
        f.write(png_header)
        f.write(zip_buffer.getvalue())

    print("[+] Polyglot file created as 'polyglot.png'")

if __name__ == '__main__':
    print("=" * 60)
    print("Hidden in Plain Sight - Challenge Creator")
    print("=" * 60)

    print("\n[1] Creating steganography image...")
    create_stego_image()

    print("\n[2] Creating ZIP with hidden file...")
    create_zip_with_hidden_file()

    print("\n[3] Creating polyglot file...")
    create_polyglot_file()

    print("\n[+] All challenge files created!")
    print("\nChallenge hints:")
    print("- hidden.png: Look at the bits...")
    print("- secret.zip: What's in the archive?")
    print("- polyglot.png: Is this really just an image?")
