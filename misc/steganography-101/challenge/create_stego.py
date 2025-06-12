#!/usr/bin/env python3
"""
Steganography 101 - Challenge Creator
Creates images with hidden flags using various techniques
"""

from PIL import Image
import os

def create_lsb_challenge():
    """
    Create an image with flag hidden in LSB of RGB channels
    Flag: CTF{lsb_st3g4n0gr4phy_b4s1cs}
    """
    width, height = 100, 100

    # Create a colorful image
    img = Image.new('RGB', (width, height))
    pixels = img.load()

    for x in range(width):
        for y in range(height):
            r = (x * 2) % 256
            g = (y * 2) % 256
            b = ((x + y) * 2) % 256
            pixels[x, y] = (r, g, b)

    # Flag to hide
    flag = "CTF{lsb_st3g4n0gr4phy_b4s1cs}"
    flag_bytes = flag.encode('utf-8')

    # Convert to bits with length prefix
    length = len(flag_bytes)
    length_bits = format(length, '032b')  # 32-bit length prefix
    flag_bits = ''.join(format(byte, '08b') for byte in flag_bytes)
    all_bits = length_bits + flag_bits

    # Embed in LSB of RGB channels (3 bits per pixel)
    bit_index = 0
    for x in range(width):
        for y in range(height):
            if bit_index >= len(all_bits):
                break

            r, g, b = pixels[x, y]

            # Modify LSB of each channel
            if bit_index < len(all_bits):
                r = (r & 0xFE) | int(all_bits[bit_index])
                bit_index += 1
            if bit_index < len(all_bits):
                g = (g & 0xFE) | int(all_bits[bit_index])
                bit_index += 1
            if bit_index < len(all_bits):
                b = (b & 0xFE) | int(all_bits[bit_index])
                bit_index += 1

            pixels[x, y] = (r, g, b)

        if bit_index >= len(all_bits):
            break

    img.save('challenge1.png', 'PNG')
    print(f"[+] Created challenge1.png (LSB in RGB)")
    print(f"    Hidden: {flag}")
    print(f"    Bits embedded: {bit_index}")

def create_bit_plane_challenge():
    """
    Create an image with visible pattern in specific bit plane
    Flag is hidden in bit 1 (second least significant bit)
    Flag: CTF{b1t_pl4n3_4n4lys1s}
    """
    width, height = 200, 50

    # Create white background
    img = Image.new('RGB', (width, height), color='white')
    pixels = img.load()

    # The flag as a visual pattern
    flag_text = "CTF{b1t_pl4n3_4n4lys1s}"

    # Each character will be 8 pixels wide (one per bit)
    x_offset = 10
    for char in flag_text:
        char_bits = format(ord(char), '08b')
        for bit in char_bits:
            # Draw a vertical line for each bit
            for y in range(height):
                r, g, b = pixels[x_offset, y]
                if bit == '1':
                    # Set bit 1
                    r = r | 0x02
                else:
                    # Clear bit 1
                    r = r & 0xFD
                pixels[x_offset, y] = (r, g, b)
            x_offset += 1

    # Add some visual noise
    import random
    random.seed(42)
    for x in range(width):
        for y in range(height):
            r, g, b = pixels[x, y]
            # Randomize LSB to add noise
            r = (r & 0xFE) | random.randint(0, 1)
            g = (g & 0xFE) | random.randint(0, 1)
            b = (b & 0xFE) | random.randint(0, 1)
            pixels[x, y] = (r, g, b)

    img.save('challenge2.png', 'PNG')
    print(f"[+] Created challenge2.png (Bit plane encoding)")
    print(f"    Hidden: {flag_text}")

def create_append_challenge():
    """
    Create an image with data appended after the image data
    Flag: CTF{f1l3_4pp3nd3d_d4t4}
    """
    # Create a simple image
    img = Image.new('RGB', (50, 50), color='blue')
    img.save('challenge3.png', 'PNG')

    # Append data after the PNG
    flag = b"CTF{f1l3_4pp3nd3d_d4t4}"
    hidden_data = b"\n\n--- HIDDEN DATA ---\n" + flag + b"\n--- END ---\n"

    with open('challenge3.png', 'ab') as f:
        f.write(hidden_data)

    print(f"[+] Created challenge3.png (Appended data)")
    print(f"    Hidden: {flag.decode()}")

def create_metadata_challenge():
    """
    Create an image with flag in EXIF metadata
    Flag: CTF{m3t4d4t4_1s_1mp0rt4nt}
    """
    from PIL import PngImagePlugin

    img = Image.new('RGB', (100, 100), color='green')

    # Add metadata
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Author", "CTF Challenge Creator")
    meta.add_text("Description", "A simple green image")
    meta.add_text("Comment", "CTF{m3t4d4t4_1s_1mp0rt4nt}")
    meta.add_text("Software", "Paint.NET v4.2.16")

    img.save('challenge4.png', 'PNG', pnginfo=meta)

    print(f"[+] Created challenge4.png (Metadata)")
    print(f"    Hidden in Comment field: CTF{{m3t4d4t4_1s_1mp0rt4nt}}")

def create_palette_challenge():
    """
    Create an image using palette where the order encodes the flag
    Flag: CTF{p4l3tt3_0rd3r}
    """
    # Create a paletted image
    img = Image.new('P', (100, 100))

    # The flag encoded in palette indices
    flag = "CTF{p4l3tt3_0rd3r}"

    # Create a palette (768 values: 256 RGB triplets)
    palette = []
    for i in range(256):
        palette.extend([i, i, i])  # Grayscale palette

    img.putpalette(palette)

    # Encode flag in pixel values
    pixels = img.load()
    x, y = 0, 0
    for char in flag:
        pixels[x, y] = ord(char)
        x += 1
        if x >= 100:
            x = 0
            y += 1

    # Fill rest with noise
    import random
    for px in range(100):
        for py in range(100):
            if pixels[px, py] == 0:
                pixels[px, py] = random.randint(128, 255)

    img.save('challenge5.png', 'PNG')

    print(f"[+] Created challenge5.png (Palette indices)")
    print(f"    Hidden in pixel values: {flag}")

def main():
    print("=" * 60)
    print("Steganography 101 - Challenge Creator")
    print("=" * 60)

    # Create output directory
    os.makedirs('challenges', exist_ok=True)
    os.chdir('challenges')

    create_lsb_challenge()
    print()
    create_bit_plane_challenge()
    print()
    create_append_challenge()
    print()
    create_metadata_challenge()
    print()
    create_palette_challenge()

    print("\n" + "=" * 60)
    print("All challenges created in ./challenges/")
    print("=" * 60)
    print("\nHints:")
    print("  challenge1.png - Look at the bits...")
    print("  challenge2.png - Try looking at different bit planes")
    print("  challenge3.png - Is there more than meets the eye?")
    print("  challenge4.png - Check the image properties")
    print("  challenge5.png - What do the pixel values mean?")

if __name__ == '__main__':
    main()
