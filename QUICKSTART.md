# Quick Start Guide

This guide helps you quickly set up and run the CTF challenges.

## Prerequisites

```bash
# Python packages
pip install flask pillow pwntools scapy

# System tools (Ubuntu/Debian)
sudo apt install gcc gdb binutils wireshark

# Optional tools
pip install zsteg  # LSB steganography
```

## Challenge Setup

### Web Challenges

```bash
# SQL Injection 101
cd web/sql-injection-101
docker build -t ctf-sqli .
docker run -p 5000:5000 ctf-sqli

# XSS Filter Bypass
cd web/xss-filter-bypass
docker build -t ctf-xss .
docker run -p 5001:5001 ctf-xss
```

### Crypto Challenges

```bash
# Weak RSA
cd crypto/weak-rsa
python3 challenge/setup.py  # Generate challenge files

# Classic Ciphers
cd crypto/classic-ciphers
python3 challenge/solver.py  # Run the solver
```

### Reverse Engineering

```bash
# License Checker
cd reverse/license-checker
gcc -o license_checker challenge/license_checker.c
./license_checker test

# Stack Overflow 101
cd reverse/stack-overflow-101
gcc -fno-stack-protector -z execstack -no-pie -o stack_overflow challenge/stack_overflow.c
./stack_overflow test
```

### Binary Exploitation

```bash
# Buffer Overflow Basics
cd binary/buffer-overflow-basics
gcc -fno-stack-protector -z execstack -no-pie -o vuln challenge/vuln.c
./vuln $(python3 -c 'print("A"*72)')
```

### Forensics

```bash
# Hidden in Plain Sight
cd forensics/hidden-in-plain-sight
python3 challenge/create_challenge.py  # Generate challenge files

# Packet Analysis
cd forensics/packet-analysis
python3 challenge/create_pcap.py  # Generate PCAP (requires scapy)
```

### Miscellaneous

```bash
# Steganography 101
cd misc/steganography-101
python3 challenge/create_stego.py  # Generate challenge images
```

## Solution Verification

Each challenge has a `WRITEUP.md` with complete solutions and often a solver script.

```bash
# Example: Verify SQL Injection solution
python3 web/sql-injection-101/solution.py

# Example: Run crypto solver
python3 crypto/classic-ciphers/challenge/solver.py
```

## Directory Structure

```
17-ctf-writeups/
├── README.md              # Main documentation
├── QUICKSTART.md          # This file
├── web/
│   ├── sql-injection-101/
│   │   ├── challenge/
│   │   ├── WRITEUP.md
│   │   └── solution.py
│   └── xss-filter-bypass/
│       ├── challenge/
│       ├── WRITEUP.md
│       └── solution.py
├── crypto/
│   ├── weak-rsa/
│   └── classic-ciphers/
├── reverse/
│   ├── license-checker/
│   └── stack-overflow-101/
├── forensics/
│   ├── hidden-in-plain-sight/
│   └── packet-analysis/
├── binary/
│   └── buffer-overflow-basics/
└── misc/
    └── steganography-101/
```

## Learning Path

1. Start with **Classic Ciphers** (easiest)
2. Try **SQL Injection 101** (web basics)
3. Move to **License Checker** (reverse engineering)
4. Attempt **Buffer Overflow Basics** (binary exploitation)
5. Challenge yourself with **Weak RSA** (crypto)
6. Explore **XSS Filter Bypass** (advanced web)
7. Finish with **Forensics** challenges

## Getting Help

- Each `WRITEUP.md` contains detailed explanations
- Solution scripts demonstrate working exploits
- Check the hints in challenge descriptions
