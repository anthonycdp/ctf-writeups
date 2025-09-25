# CTF Write-ups Collection

A comprehensive collection of Capture The Flag challenge write-ups demonstrating security research methodology, vulnerability analysis, and exploitation techniques across multiple domains.

## Overview

This repository documents my approach to solving CTF challenges, showcasing:
- **Methodical problem-solving** - Breaking down complex problems into manageable steps
- **Tool proficiency** - Effective use of industry-standard security tools
- **Deep technical understanding** - Explaining the "why" behind each technique
- **Clear communication** - Making complex concepts accessible

## Challenge Categories

### Web Exploitation
| Challenge | Difficulty | Topics |
|-----------|------------|--------|
| [SQL Injection 101](./web/sql-injection-101/) | Easy | SQLi, Authentication Bypass |
| [XSS Filter Bypass](./web/xss-filter-bypass/) | Medium | Cross-Site Scripting, WAF Evasion |

### Cryptography
| Challenge | Difficulty | Topics |
|-----------|------------|--------|
| [Weak RSA](./crypto/weak-rsa/) | Medium | RSA, Factorization, Small Exponents |
| [Classic Ciphers](./crypto/classic-ciphers/) | Easy | Substitution, Transposition, Frequency Analysis |

### Reverse Engineering
| Challenge | Difficulty | Topics |
|-----------|------------|--------|
| [License Checker](./reverse/license-checker/) | Easy | Static Analysis, Patching |
| [Stack Overflow 101](./reverse/stack-overflow-101/) | Medium | Binary Analysis, Control Flow |

### Forensics
| Challenge | Difficulty | Topics |
|-----------|------------|--------|
| [Hidden in Plain Sight](./forensics/hidden-in-plain-sight/) | Easy | Steganography, Metadata |
| [Packet Analysis](./forensics/packet-analysis/) | Medium | Network Forensics, Protocol Analysis |

### Binary Exploitation
| Challenge | Difficulty | Topics |
|-----------|------------|--------|
| [Buffer Overflow Basics](./binary/buffer-overflow-basics/) | Easy | Stack Overflow, Shellcode |

### Miscellaneous
| Challenge | Difficulty | Topics |
|-----------|------------|--------|
| [Steganography 101](./misc/steganography-101/) | Easy | Image Analysis, LSB Encoding |

## Skills Demonstrated

### Technical Skills
- **Web Security**: SQL injection, XSS, CSRF, authentication bypasses
- **Cryptography**: Classical ciphers, RSA vulnerabilities, hash cracking
- **Reverse Engineering**: Disassembly, decompilation, binary patching
- **Binary Exploitation**: Buffer overflows, ROP chains, memory corruption
- **Forensics**: File carving, packet analysis, memory forensics
- **Tools**: Burp Suite, Ghidra, Wireshark, GDB, John the Ripper, CyberChef

### Methodology
1. **Reconnaissance** - Information gathering and enumeration
2. **Analysis** - Understanding the challenge structure
3. **Hypothesis** - Developing potential attack vectors
4. **Exploitation** - Executing the attack
5. **Documentation** - Recording the process and findings

## Tools Reference

### Web Exploitation
```bash
# SQLMap for automated SQL injection
sqlmap -u "http://target.com/page?id=1" --dbs

# Burp Suite for intercepting requests
# Manual testing with curl
curl -X POST "http://target.com/login" -d "user=admin&pass=test"
```

### Reverse Engineering
```bash
# Static analysis with Ghidra/Eye
ghidra

# Quick disassembly
objdump -d binary

# String extraction
strings binary | grep -i flag
```

### Binary Exploitation
```bash
# GDB with pwndbg
gdb ./binary

# Check security features
checksec --file=./binary
```

### Forensics
```bash
# File analysis
file unknown_file
xxd unknown_file | head

# Network analysis
tshark -r capture.pcap -Y "http"
```

## Challenge Source Code

Each challenge includes:
- **Source code** - The vulnerable application or challenge files
- **Dockerfile** (where applicable) - Reproducible environment setup
- **Solution scripts** - Automated exploitation tools
- **Detailed write-up** - Step-by-step methodology

## Quick Start

```bash
# Install dependencies
make setup

# Generate challenge artifacts (images, pcaps, etc.)
make generate

# Compile C binaries (requires gcc)
make build

# Start all Docker containers
make docker-up

# Run all solutions
make run-all

# Run tests
make test
```

## Running the Challenges

### Web Challenges (Docker)
```bash
# Start all containers
make docker-up

# Or individually:
docker-compose up -d sql-injection  # Port 5001
docker-compose up -d xss-filter     # Port 5002
```

### Binary Challenges
```bash
# Compile with make
make build

# Or manually:
gcc -fno-stack-protector -z execstack -no-pie -o vuln challenge/vuln.c
```

## Learning Path

Recommended order for beginners:
1. **Classic Ciphers** - Fundamental crypto concepts
2. **Hidden in Plain Sight** - Basic forensics
3. **SQL Injection 101** - Web security fundamentals
4. **License Checker** - Introduction to RE
5. **Buffer Overflow Basics** - Binary exploitation basics
6. **Weak RSA** - Modern cryptography
7. **XSS Filter Bypass** - Advanced web exploitation
8. **Packet Analysis** - Network forensics

## Statistics

| Metric | Count |
|--------|-------|
| Total Challenges | 9 |
| Web | 2 |
| Crypto | 2 |
| Reverse Engineering | 2 |
| Forensics | 2 |
| Binary Exploitation | 1 |
| Misc | 1 |
| Test Coverage | 122 tests |

## Project Structure

```
ctf-writeups/
├── web/           # Web exploitation challenges
├── crypto/        # Cryptography challenges
├── reverse/       # Reverse engineering challenges
├── forensics/     # Digital forensics challenges
├── binary/        # Binary exploitation challenges
├── misc/          # Miscellaneous challenges
├── tests/         # Pytest test suite
├── Makefile       # Build and run commands
└── docker-compose.yml
```

---

*These challenges are created for educational purposes. Always practice ethical hacking and obtain proper authorization before testing systems.*
