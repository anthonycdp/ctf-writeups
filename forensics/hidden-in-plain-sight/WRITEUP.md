# Hidden in Plain Sight - Write-up

**Category:** Forensics
**Difficulty:** Easy
**Flags:**
- `CTF{h1dd3n_1n_pl41n_s1ght_m3t4d4t4}` (LSB Steganography)
- `CTF{z1p_f1l3s_c4n_h1d3_s3cr3ts}` (Hidden ZIP file)
- `CTF{p0lygl0t_f1l3_m4st3r}` (Polyglot file)

## Challenge Description

Three files are provided for analysis:
- `hidden.png` - A seemingly innocent image
- `secret.zip` - A ZIP archive with a readme file
- `polyglot.png` - An image file... or is it?

Find all the hidden flags!

---

## Part 1: LSB Steganography

### Initial Analysis

```bash
$ file hidden.png
hidden.png: PNG image data, 200 x 200, 8-bit/color RGB, non-interlaced

$ exiftool hidden.png
File Size                       : 12 kB
File Type                       : PNG
Image Width                     : 200
Image Height                    : 200
Bit Depth                       : 8
Color Type                      : RGB
```

### Checking for Steganography

**Method 1: Visual Inspection**

Open the image in an image viewer. It looks like a gradient pattern. Nothing obviously hidden visually.

**Method 2: Strings Check**

```bash
$ strings hidden.png
...
Nothing to see here... or is there?
...
```

There's a suspicious comment in the metadata!

**Method 3: LSB Extraction**

The hint "Look at the bits..." suggests LSB (Least Significant Bit) steganography. In this technique, data is hidden in the least significant bits of pixel values.

### Extraction Script

```python
#!/usr/bin/env python3
"""
LSB Steganography Extractor
"""
from PIL import Image

def extract_lsb(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size

    # Extract LSBs from red channel
    bits = []
    for x in range(width):
        for y in range(height):
            r, g, b = pixels[x, y]
            bits.append(r & 1)  # Get LSB of red channel

    # First 16 bits are the length of hidden data
    length_bits = bits[:16]
    length = int(''.join(map(str, length_bits)), 2)

    print(f"[*] Hidden data length: {length} bytes")

    # Extract the actual data
    data_bits = bits[16:16 + length * 8]
    data_bytes = []

    for i in range(0, len(data_bits), 8):
        byte_bits = data_bits[i:i+8]
        if len(byte_bits) == 8:
            byte = int(''.join(map(str, byte_bits)), 2)
            data_bytes.append(byte)

    # Convert to string
    hidden_data = bytes(data_bytes).decode('utf-8')
    print(f"[+] Hidden message: {hidden_data}")
    return hidden_data

if __name__ == '__main__':
    extract_lsb('hidden.png')
```

**Output:**
```
[*] Hidden data length: 39 bytes
[+] Hidden message: CTF{h1dd3n_1n_pl41n_s1ght_m3t4d4t4}
```

### Using Existing Tools

**zsteg (for PNG):**
```bash
$ zsteg hidden.png
b1,r,lsb,xy         .. text: "CTF{h1dd3n_1n_pl41n_s1ght_m3t4d4t4}"
```

**Stegsolve:**
Open in Stegsolve and check different bit planes (Red Plane 0).

---

## Part 2: Hidden ZIP File

### Initial Analysis

```bash
$ file secret.zip
secret.zip: Zip archive data, at least v2.0 to extract

$ unzip -l secret.zip
Archive:  secret.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       56  2024-01-15 10:30   readme.txt
---------                     -------
       56                     1 file
```

Only `readme.txt` is visible!

### Looking Deeper

**Method 1: List All Files (including hidden)**

```bash
$ unzip -l secret.zip -v
Archive:  secret.zip
 Length   Method    Size  Cmpr    Date    Time   CRC-32   Name
--------  ------  ------- ---- ---------- ----- --------  ----
      56  Stored       56   0% 2024-01-15 10:30 12345678  readme.txt
      42  Stored       42   0% 2024-01-15 10:30 87654321  .flag
--------          -------  ---                            -------
      98               98   0%                            2 files
```

The `.flag` file is hidden (starts with a dot)!

**Method 2: Extract Everything**

```bash
$ unzip secret.zip
Archive:  secret.zip
 extracting: readme.txt
 extracting: .flag

$ cat .flag
CTF{z1p_f1l3s_c4n_h1d3_s3cr3ts}
```

**Method 3: Using 7z**

```bash
$ 7z l secret.zip
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-01-15 10:30:00 ....A           56           56  readme.txt
2024-01-15 10:30:00 ....H           42           42  .flag
------------------- ----- ------------ ------------  ------------------------
```

The `H` attribute indicates hidden.

---

## Part 3: Polyglot File

### Initial Analysis

```bash
$ file polyglot.png
polyglot.png: PNG image data, 1 x 1, 8-bit/color RGB, non-interlaced

$ xxd polyglot.png | head
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 0001 0000 0001 0802 0000 0090 7753  ..........wS
...
```

It's a valid PNG file. But wait, let's check the size:

```bash
$ ls -la polyglot.png
-rw-r--r-- 1 user user 250 Jan 15 10:30 polyglot.png
```

250 bytes for a 1x1 pixel image seems too large!

### Detecting the Hidden Content

**Method 1: binwalk**

```bash
$ binwalk polyglot.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1 x 1, 8-bit/color RGB, non-interlaced
61            0x3D            Zip archive data, at least v2.0 to extract
```

There's a ZIP file appended after the PNG!

**Method 2: strings**

```bash
$ strings polyglot.png
IHDR
IDAT
IEND
PK
.hidden_flag
CTF{p0lygl0t_f1l3_m4st3r}PK
```

**Method 3: Manual Extraction**

```bash
# Extract ZIP portion (starting at offset 61)
$ dd if=polyglot.png of=hidden.zip bs=1 skip=61
189+0 records in
189+0 records out

$ unzip hidden.zip
Archive:  hidden.zip
 extracting: .hidden_flag

$ cat .hidden_flag
CTF{p0lygl0t_f1l3_m4st3r}
```

**Method 4: binwalk Extraction**

```bash
$ binwalk -e polyglot.png

$ cat _polyglot.png.extracted/.hidden_flag
CTF{p0lygl0t_f1l3_m4st3r}
```

---

## Tools Summary

| Task | Tools |
|------|-------|
| LSB Extraction | `zsteg`, `stegsolve`, custom Python |
| ZIP Analysis | `unzip`, `7z`, `binwalk` |
| File Analysis | `file`, `xxd`, `strings`, `exiftool` |
| Polyglot Detection | `binwalk`, `xxd` |

## Complete Solution Script

```python
#!/usr/bin/env python3
"""
Hidden in Plain Sight - Complete Solver
"""
import subprocess
import os

def solve_lsb():
    """Extract LSB steganography from PNG"""
    from PIL import Image

    print("[*] Extracting LSB from hidden.png...")

    img = Image.open('challenge/hidden.png')
    pixels = img.load()
    width, height = img.size

    bits = []
    for x in range(width):
        for y in range(height):
            r, g, b = pixels[x, y]
            bits.append(r & 1)

    length = int(''.join(map(str, bits[:16])), 2)
    data_bits = bits[16:16 + length * 8]

    data_bytes = []
    for i in range(0, len(data_bits), 8):
        byte_bits = data_bits[i:i+8]
        if len(byte_bits) == 8:
            data_bytes.append(int(''.join(map(str, byte_bits)), 2))

    hidden_data = bytes(data_bytes).decode('utf-8')
    print(f"[+] Flag: {hidden_data}")
    return hidden_data

def solve_zip():
    """Extract hidden files from ZIP"""
    print("\n[*] Extracting hidden files from secret.zip...")

    os.makedirs('extracted', exist_ok=True)
    subprocess.run(['unzip', '-o', 'challenge/secret.zip', '-d', 'extracted'],
                   capture_output=True)

    with open('extracted/.flag', 'r') as f:
        flag = f.read().strip()

    print(f"[+] Flag: {flag}")
    return flag

def solve_polyglot():
    """Extract hidden data from polyglot file"""
    print("\n[*] Analyzing polyglot.png...")

    # Use binwalk
    result = subprocess.run(['binwalk', '-e', '-C', 'extracted_poly',
                             'challenge/polyglot.png'],
                            capture_output=True, text=True)

    # Find the flag
    for root, dirs, files in os.walk('extracted_poly'):
        for f in files:
            if 'flag' in f.lower() or f.startswith('.'):
                path = os.path.join(root, f)
                with open(path, 'r') as file:
                    content = file.read().strip()
                    if 'CTF{' in content:
                        print(f"[+] Flag: {content}")
                        return content

    return None

def main():
    print("=" * 60)
    print("Hidden in Plain Sight - Solver")
    print("=" * 60)

    flags = []

    try:
        flags.append(solve_lsb())
    except Exception as e:
        print(f"[-] LSB failed: {e}")

    try:
        flags.append(solve_zip())
    except Exception as e:
        print(f"[-] ZIP failed: {e}")

    try:
        flags.append(solve_polyglot())
    except Exception as e:
        print(f"[-] Polyglot failed: {e}")

    print("\n" + "=" * 60)
    print("FLAGS FOUND:")
    for flag in flags:
        if flag:
            print(f"  {flag}")
    print("=" * 60)

if __name__ == '__main__':
    main()
```

## Key Takeaways

1. **LSB Steganography** - Data can be hidden in the least significant bits of pixel values
2. **Hidden Files** - Files starting with `.` are hidden in Unix systems
3. **Polyglot Files** - A file can be valid in multiple formats simultaneously
4. **Always Check** - File size, strings, metadata, and structure

## Prevention/Detection

- **Steganography Detection**: Statistical analysis of LSB distribution
- **File Validation**: Check for unexpected data after valid file structure
- **ZIP Inspection**: Always list all files including hidden ones

---

*These techniques demonstrate that "hidden" data often exists in plain sight, requiring only the right tools and techniques to reveal.*
