# Steganography 101 - Write-up

**Category:** Miscellaneous
**Difficulty:** Easy
**Flags:**
- `CTF{lsb_st3g4n0gr4phy_b4s1cs}` (LSB in RGB)
- `CTF{b1t_pl4n3_4n4lys1s}` (Bit Plane)
- `CTF{f1l3_4pp3nd3d_d4t4}` (Appended Data)
- `CTF{m3t4d4t4_1s_1mp0rt4nt}` (Metadata)
- `CTF{p4l3tt3_0rd3r}` (Palette)

## Challenge Description

Five images with hidden flags using different steganography techniques. Find all the flags!

---

## Challenge 1: LSB Steganography

### Initial Analysis

```bash
$ file challenge1.png
challenge1.png: PNG image data, 100 x 100, 8-bit/color RGB, non-interlaced

$ ls -la challenge1.png
-rw-r--r-- 1 user user 10532 Jan 15 10:30 challenge1.png
```

### Detection

The hint "Look at the bits..." suggests LSB steganography.

**Using zsteg:**
```bash
$ zsteg challenge1.png
b1,r,lsb,xy         .. text: "CTF{lsb_st3g4n0gr4phy_b4s1cs}"
```

**Manual Extraction:**

```python
#!/usr/bin/env python3
from PIL import Image

def extract_lsb(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size

    # Extract LSB from RGB channels
    bits = []
    for x in range(width):
        for y in range(height):
            r, g, b = pixels[x, y]
            bits.extend([r & 1, g & 1, b & 1])

    # First 32 bits are length
    length = int(''.join(map(str, bits[:32])), 2)

    # Extract data
    data_bits = bits[32:32 + length * 8]
    data_bytes = []

    for i in range(0, len(data_bits), 8):
        byte_bits = data_bits[i:i+8]
        if len(byte_bits) == 8:
            data_bytes.append(int(''.join(map(str, byte_bits)), 2))

    hidden = bytes(data_bytes).decode('utf-8')
    print(f"[+] Hidden message: {hidden}")
    return hidden

extract_lsb('challenge1.png')
# Output: CTF{lsb_st3g4n0gr4phy_b4s1cs}
```

---

## Challenge 2: Bit Plane Analysis

### Initial Analysis

```bash
$ file challenge2.png
challenge2.png: PNG image data, 200 x 50, 8-bit/color RGB, non-interlaced
```

The image looks like a colorful gradient with some noise.

### Detection

"Try looking at different bit planes" - we need to isolate specific bits.

**Using Stegsolve:**
1. Open image in Stegsolve
2. Click through different bit planes
3. Bit plane 1 (second LSB) shows vertical lines

**Using Python:**

```python
#!/usr/bin/env python3
from PIL import Image

def extract_bit_plane(image_path, bit_num):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size

    # Extract specific bit plane
    result = Image.new('L', (width, height))
    result_pixels = result.load()

    for x in range(width):
        for y in range(height):
            r, g, b = pixels[x, y]
            bit = (r >> bit_num) & 1
            result_pixels[x, y] = bit * 255

    return result

# Extract bit 1
bit1_img = extract_bit_plane('challenge2.png', 1)
bit1_img.save('bit_plane_1.png')
```

**Reading the Pattern:**

The bit plane shows vertical stripes. Each 8 stripes represent one ASCII character:

```python
def decode_bit_plane(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size

    # Read bit 1 of red channel
    chars = []
    for x in range(10, width, 8):  # Start at offset 10
        byte_bits = []
        for i in range(8):
            r, g, b = pixels[x + i, 0]
            byte_bits.append((r >> 1) & 1)

        char_val = int(''.join(map(str, byte_bits)), 2)
        if 32 <= char_val <= 126:
            chars.append(chr(char_val))

    message = ''.join(chars)
    print(f"[+] Hidden message: {message}")
    return message

decode_bit_plane('challenge2.png')
# Output: CTF{b1t_pl4n3_4n4lys1s}
```

---

## Challenge 3: Appended Data

### Initial Analysis

```bash
$ file challenge3.png
challenge3.png: PNG image data, 50 x 50, 8-bit/color RGB, non-interlaced

$ ls -la challenge3.png
-rw-r--r-- 1 user user 1253 Jan 15 10:30 challenge3.png
```

The file size seems reasonable for a 50x50 image, but let's look deeper.

### Detection

**Using strings:**
```bash
$ strings challenge3.png
...
IEND
--- HIDDEN DATA ---
CTF{f1l3_4pp3nd3d_d4t4}
--- END ---
```

**Using xxd:**
```bash
$ xxd challenge3.png | tail
000004c0: 0000 0000 0000 0000 0000 0000 4945 4e44  ..............IEND
000004d0: ae42 6082 0a0a 2d2d 2d20 4849 4444  .....--- HIDD
000004e0: 454e 2044 4154 4120 2d2d 2d0a 4354  EN DATA ---.CT
000004f0: 467b 6631 6c33 5f34 7070 336e 6433  F{f1l3_4pp3nd3d
00000500: 645f 6434 7434 7d0a 2d2d 2d20 454e  d_d4t4}.--- EN
00000510: 4420 2d2d 2d0a                           D ---.
```

**After PNG IEND marker**, there's additional data!

### Extraction

```bash
# Find PNG end marker (IEND + CRC = 12 bytes after "IEND")
# IEND is at offset where strings show it

# Extract after PNG
$ dd if=challenge3.png bs=1 skip=1241
CTF{f1l3_4pp3nd3d_d4t4}
--- END ---
```

Or using Python:
```python
with open('challenge3.png', 'rb') as f:
    data = f.read()

# Find IEND marker
iend = data.find(b'IEND')
if iend != -1:
    # Skip IEND + 8 bytes CRC
    hidden = data[iend + 12:]
    print(hidden.decode())
# Output: CTF{f1l3_4pp3nd3d_d4t4}
```

---

## Challenge 4: Metadata

### Initial Analysis

```bash
$ file challenge4.png
challenge4.png: PNG image data, 100 x 100, 8-bit/color RGB, non-interlaced
```

### Detection

**Using exiftool:**
```bash
$ exiftool challenge4.png
File Name                       : challenge4.png
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 100
Image Height                    : 100
Bit Depth                       : 8
Color Type                      : RGB
Author                          : CTF Challenge Creator
Description                     : A simple green image
Comment                         : CTF{m3t4d4t4_1s_1mp0rt4nt}
Software                        : Paint.NET v4.2.16
```

The flag is in the `Comment` field!

**Using strings:**
```bash
$ strings challenge4.png | grep -i ctf
CTF{m3t4d4t4_1s_1mp0rt4nt}
```

### Extraction

```python
from PIL import Image
from PIL import PngImagePlugin

img = Image.open('challenge4.png')
info = img.info

print("Metadata:")
for key, value in info.items():
    print(f"  {key}: {value}")
    if 'CTF{' in str(value):
        print(f"  [+] Flag found: {value}")
```

---

## Challenge 5: Palette Indices

### Initial Analysis

```bash
$ file challenge5.png
challenge5.png: PNG image data, 100 x 100, 8-bit colormap, non-interlaced
```

Note: "8-bit colormap" means it's a paletted image!

### Detection

**Using identify (ImageMagick):**
```bash
$ identify -verbose challenge5.png | head -20
Image: challenge5.png
  Format: PNG (Portable Network Graphics)
  Type: Palette
  Colorspace: sRGB
  ...
```

**Using Python:**

```python
from PIL import Image

img = Image.open('challenge5.png')
print(f"Mode: {img.mode}")  # P = Palette mode

pixels = img.load()

# Read pixel values (palette indices)
for y in range(10):
    row = []
    for x in range(20):
        row.append(pixels[x, y])
    print(row)

# Notice the first few values look like ASCII codes!
```

### Extraction

```python
def extract_palette_message(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size

    # Collect pixel values
    chars = []
    for y in range(height):
        for x in range(width):
            val = pixels[x, y]
            if 32 <= val <= 126:  # Printable ASCII
                chars.append(chr(val))
            if '}' in ''.join(chars):
                break
        if '}' in ''.join(chars):
            break

    message = ''.join(chars)
    # Find flag pattern
    import re
    match = re.search(r'CTF\{[^}]+\}', message)
    if match:
        print(f"[+] Flag: {match.group()}")
        return match.group()

extract_palette_message('challenge5.png')
# Output: CTF{p4l3tt3_0rd3r}
```

---

## Complete Solver Script

```python
#!/usr/bin/env python3
"""
Steganography 101 - Complete Solver
"""
from PIL import Image
import re

def solve_lsb(path):
    """Extract LSB from RGB channels"""
    print(f"\n[*] Analyzing {path} for LSB...")

    img = Image.open(path)
    pixels = img.load()
    width, height = img.size

    bits = []
    for x in range(width):
        for y in range(height):
            r, g, b = pixels[x, y]
            bits.extend([r & 1, g & 1, b & 1])

    # Extract with length prefix
    length = int(''.join(map(str, bits[:32])), 2)
    data_bits = bits[32:32 + length * 8]

    data_bytes = []
    for i in range(0, len(data_bits), 8):
        byte_bits = data_bits[i:i+8]
        if len(byte_bits) == 8:
            data_bytes.append(int(''.join(map(str, byte_bits)), 2))

    hidden = bytes(data_bytes).decode('utf-8', errors='ignore')
    if 'CTF{' in hidden:
        print(f"[+] Flag: {hidden}")

def solve_appended(path):
    """Extract data appended after image"""
    print(f"\n[*] Checking {path} for appended data...")

    with open(path, 'rb') as f:
        data = f.read()

    # Find IEND
    iend = data.find(b'IEND')
    if iend != -1:
        hidden = data[iend + 12:].decode('utf-8', errors='ignore')
        match = re.search(r'CTF\{[^}]+\}', hidden)
        if match:
            print(f"[+] Flag: {match.group()}")

def solve_metadata(path):
    """Extract metadata"""
    print(f"\n[*] Checking {path} metadata...")

    img = Image.open(path)
    for key, value in img.info.items():
        if 'CTF{' in str(value):
            print(f"[+] Flag in {key}: {value}")

def solve_palette(path):
    """Extract palette-encoded message"""
    print(f"\n[*] Checking {path} palette indices...")

    img = Image.open(path)
    if img.mode != 'P':
        return

    pixels = img.load()
    width, height = img.size

    chars = []
    for y in range(height):
        for x in range(width):
            val = pixels[x, y]
            if 32 <= val <= 126:
                chars.append(chr(val))

    message = ''.join(chars)
    match = re.search(r'CTF\{[^}]+\}', message)
    if match:
        print(f"[+] Flag: {match.group()}")

def main():
    print("=" * 60)
    print("Steganography 101 - Solver")
    print("=" * 60)

    solve_lsb('challenge1.png')
    solve_appended('challenge3.png')
    solve_metadata('challenge4.png')
    solve_palette('challenge5.png')

if __name__ == '__main__':
    main()
```

---

## Tools Summary

| Technique | Tools |
|-----------|-------|
| LSB | `zsteg`, `stegsolve`, `steghide` |
| Bit Plane | `stegsolve`, Python PIL |
| Appended Data | `strings`, `xxd`, `binwalk` |
| Metadata | `exiftool`, `identify`, PIL |
| Palette | PIL, Python |

## Detection Tips

1. **Always check:**
   - File size vs expected size
   - Metadata fields
   - Data after file end marker
   - Unusual color patterns

2. **Visual inspection:**
   - Different bit planes
   - Color histograms
   - Zoom in on edges

3. **Automated tools:**
   - `zsteg` for PNG
   - `steghide` for JPEG
   - `binwalk` for embedded files

---

*Steganography hides data in plain sight. Always look beyond what's immediately visible!*
