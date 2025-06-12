# License Checker - Write-up

**Category:** Reverse Engineering
**Difficulty:** Easy
**Flag:** `CTF{r3v3rs3_3ng1n33r1ng_m4st3r}`

## Challenge Description

A license validation program needs to be reverse engineered to find the correct license key. The program accepts a license key as a command-line argument and validates it against several checks.

```bash
$ ./license_checker XXXX-XXXX-XXXX-XXXX
```

## Initial Analysis

### Step 1: Running the Program

```bash
$ ./license_checker test
License Checker v1.0
Usage: ./license_checker <license_key>

License format: XXXX-XXXX-XXXX-XXXX
Where X is alphanumeric (A-Z, 0-9)
```

```bash
$ ./license_checker AAAA-BBBB-CCCC-DDDD
[*] Validating license: AAAA-BBBB-CCCC-DDDD

[+] Format check passed
[-] Segment 1 validation failed!

[-] License validation failed!
```

The program reveals that validation happens in segments.

### Step 2: Static Analysis with Strings

```bash
$ strings license_checker
...
CTF{r3v3rs3_3ng1n33r1ng_m4st3r}
SECRETKEY2024
Invalid format!
Format check passed
Segment %d validation failed!
Segment %d validated: %s
Invalid checksum!
Checksum verified
...
```

Interesting! The flag is directly in the binary. But in a real CTF, we'd need to derive the license.

### Step 3: Disassembly with Ghidra/objdump

```bash
$ objdump -d license_checker | less
```

Looking for main function and validation logic:

```asm
<main>:
    ...
    call check_debugger
    test eax, eax
    jne debugger_detected
    ...
    call validate_license
    ...
```

### Step 4: Analyzing Validation Functions

#### Format Check

```c
int check_format(const char *license) {
    if (strlen(license) != 19) return 0;

    // Check dash positions
    if (license[4] != '-' || license[9] != '-' || license[14] != '-') {
        return 0;
    }

    // Check alphanumeric characters
    for (int i = 0; i < 19; i++) {
        if (i == 4 || i == 9 || i == 14) continue;
        char c = license[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
            return 0;
        }
    }
    return 1;
}
```

Format: `XXXX-XXXX-XXXX-XXXX` (uppercase letters A-Z and digits 0-9)

#### Segment Validation

```c
int validate_segment(const char *segment, int segment_num) {
    int sum = 0;
    int product = 1;

    for (int i = 0; i < 4; i++) {
        char c = segment[i];
        int val;
        if (c >= 'A' && c <= 'Z') val = c - 'A' + 10;
        else val = c - '0';
        sum += val;
        product *= (val % 10) + 1;
    }

    switch (segment_num) {
        case 1: return sum == 42;
        case 2: return segment[0] == 'C' && segment[3] == '4';
        case 3: return all_numeric(segment);
        case 4: return product == 36;
    }
}
```

#### Checksum Calculation

```c
#define CHECKSUM 0x29F0  // 10736 in decimal

int calculate_checksum(const char *license) {
    int sum = 0;
    for (int i = 0; license[i] != '\0'; i++) {
        sum += (unsigned char)license[i] * (i + 1);
    }
    return sum;
}
```

## Solving Each Segment

### Segment 1: Sum == 42

Characters are converted to values:
- Digits 0-9 → 0-9
- Letters A-Z → 10-35

We need four characters whose values sum to 42.

**Solution:** `KKKK` (K=20, so 20+20+20+20=80... that's too high)

Let me recalculate:
- A=10, B=11, C=12, D=13, E=14, F=15, G=16, H=17, I=18, J=19, K=20
- 9=9

Possible solutions:
- `9999` = 9+9+9+9 = 36 ❌
- `9AAA` = 9+10+10+10 = 39 ❌
- `ABCD` = 10+11+12+13 = 46 ❌
- `99AA` = 9+9+10+10 = 38 ❌
- `9ABD` = 9+10+11+13 = 43 ❌
- `9ABC` = 9+10+11+12 = 42 ✅

**Segment 1: `9ABC`**

### Segment 2: First='C', Last='4'

This one is straightforward:
- First character must be 'C'
- Last character must be '4'
- Middle two can be anything

**Simplest solution: `CXx4`** - but wait, lowercase might not work.

Looking at format check: only A-Z and 0-9 allowed.

**Solution: `CXX4`** where X is alphanumeric.

**Segment 2: `CXX4`** (or any valid like `CA04`, `CZZ4`, etc.)

### Segment 3: All Numeric

All four characters must be digits 0-9.

**Segment 3: `1234`** (or any 4-digit combination)

### Segment 4: Product == 36

The product calculation is:
```c
product *= (val % 10) + 1;
```

For each character:
- val % 10 gives last digit of value
- +1 ensures no multiplication by 0

So we need: product of four ((val % 10) + 1) values = 36

36 = 2 × 3 × 3 × 2

Values that give these remainders:
- (val % 10) + 1 = 2 → val % 10 = 1 → val ends in 1 (1, 11, 21, 31)
- (val % 10) + 1 = 3 → val % 10 = 2 → val ends in 2 (2, 12, 22, 32)

Possible characters:
- val=1 → '1'
- val=11 → 'B'
- val=21 → 'L'
- val=31 → 'V'

- val=2 → '2'
- val=12 → 'C'
- val=22 → 'M'
- val=32 → 'W'

Solution: `1BCD` with factors 2,3,3,2... wait let me recalculate.

If characters are '1','2','2','3':
- '1' → val=1 → (1%10)+1 = 2
- '2' → val=2 → (2%10)+1 = 3
- '2' → val=2 → (2%10)+1 = 3
- '3' → val=3 → (3%10)+1 = 4
- Product = 2 × 3 × 3 × 4 = 72 ❌

Let's try '1','2','2','1':
- Product = 2 × 3 × 3 × 2 = 36 ✅

**Segment 4: `1221`** or **`B22B`** etc.

## Checksum Constraint

Now we need to find values that also satisfy checksum = 10736.

```python
def calculate_checksum(license):
    total = 0
    for i, c in enumerate(license):
        total += ord(c) * (i + 1)
    return total
```

Let's test with: `9ABC-CXX4-1234-1221`

```python
license = "9ABC-CXX4-1234-1221"
checksum = sum(ord(c) * (i+1) for i, c in enumerate(license))
print(checksum)
```

This gives us a specific value. We need to adjust to get 10736.

Since segment 2 and 3 have flexibility, we can adjust them to match the checksum.

## Solution Script

```python
#!/usr/bin/env python3
"""
License Checker - Solver
"""
import itertools

def char_value(c):
    """Convert character to validation value"""
    if c >= 'A' and c <= 'Z':
        return ord(c) - ord('A') + 10
    elif c >= '0' and c <= '9':
        return ord(c) - ord('0')
    return 0

def segment1_valid(segment):
    """Sum of values == 42"""
    return sum(char_value(c) for c in segment) == 42

def segment2_valid(segment):
    """First char 'C', last char '4'"""
    return segment[0] == 'C' and segment[3] == '4'

def segment3_valid(segment):
    """All numeric"""
    return all(c.isdigit() for c in segment)

def segment4_valid(segment):
    """Product of ((val % 10) + 1) == 36"""
    product = 1
    for c in segment:
        val = char_value(c)
        product *= (val % 10) + 1
    return product == 36

def calculate_checksum(license):
    """Calculate license checksum"""
    return sum(ord(c) * (i + 1) for i, c in enumerate(license))

# Generate valid segment 1 candidates
segment1_options = []
chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
for combo in itertools.product(chars, repeat=4):
    seg = ''.join(combo)
    if segment1_valid(seg):
        segment1_options.append(seg)
print(f"[*] Found {len(segment1_options)} valid segment 1 options")

# Generate valid segment 2 candidates
segment2_options = []
for combo in itertools.product(chars, repeat=2):
    seg = 'C' + ''.join(combo) + '4'
    if segment2_valid(seg):
        segment2_options.append(seg)
print(f"[*] Found {len(segment2_options)} valid segment 2 options")

# Generate valid segment 3 candidates
segment3_options = []
digits = '0123456789'
for combo in itertools.product(digits, repeat=4):
    seg = ''.join(combo)
    if segment3_valid(seg):
        segment3_options.append(seg)
print(f"[*] Found {len(segment3_options)} valid segment 3 options")

# Generate valid segment 4 candidates
segment4_options = []
for combo in itertools.product(chars, repeat=4):
    seg = ''.join(combo)
    if segment4_valid(seg):
        segment4_options.append(seg)
print(f"[*] Found {len(segment4_options)} valid segment 4 options")

# Target checksum
TARGET_CHECKSUM = 0x29F0  # 10736

# Brute force to find matching license
print("\n[*] Searching for valid license with checksum 6715...")
for s1 in segment1_options[:100]:  # Limit for speed
    for s2 in segment2_options[:100]:
        for s3 in segment3_options:
            for s4 in segment4_options[:100]:
                license = f"{s1}-{s2}-{s3}-{s4}"
                if calculate_checksum(license) == TARGET_CHECKSUM:
                    print(f"\n[+] Found valid license: {license}")
                    print(f"[+] Checksum: {calculate_checksum(license)}")
                    exit()

print("[-] No valid license found in search space")
```

## Anti-Debugging Bypass

The program includes a simple debugger check:

```bash
$ gdb ./license_checker
(gdb) run AAAA-BBBB-CCCC-DDDD
[-] Debugger detected! Exiting...
```

**Bypass methods:**

1. **Patch the binary:**
```bash
# Find the check and NOP it out
# In Ghidra: Find "TracerPid" check, patch jumps
```

2. **Use anti-anti-debug tools:**
```bash
$ LD_PRELOAD=/usr/lib/libantidebug.so ./license_checker ...
```

3. **Static analysis only:** Just analyze the binary without running it

## Patching the Binary

Using Ghidra or xxd:

```bash
# Find the anti-debug function call
# Patch the conditional jump after check_debugger()
# Change JNE to JMP or NOP

# Example with xxd and sed:
xxd license_checker > temp.hex
# Find and modify the relevant bytes
# Convert back:
xxd -r temp.hex > license_checker_patched
chmod +x license_checker_patched
```

## Key Takeaways

1. **Static Analysis** - Understanding code without running it
2. **Pattern Recognition** - Identifying validation constraints
3. **Constraint Satisfaction** - Finding inputs that meet all criteria
4. **Anti-Debugging** - Understanding and bypassing protection mechanisms

## Tools Used

- **Ghidra** - Decompilation and analysis
- **objdump** - Disassembly
- **strings** - Quick reconnaissance
- **gdb** - Dynamic analysis (with anti-debug bypass)
- **Python** - Constraint solving

---

*This challenge demonstrates basic reverse engineering techniques applicable to real-world software analysis.*
