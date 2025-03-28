# Packet Analysis - Write-up

**Category:** Forensics
**Difficulty:** Medium
**Flags:**
- `CTF{dns_3xf1ltr4t10n_d3t3ct3d}` (DNS Exfiltration)
- `CTF{1cmp_tunn3l_h1dd3n_d4t4}` (ICMP Tunnel)
- `CTF{tcp_0pt10ns_h1d3_d4t4}` (TCP Options)
- `CTF{h77p_h34d3r_s3cr3t}` (HTTP Header)

## Challenge Description

A network capture file contains suspicious traffic. Analyze the packets to find hidden data being exfiltrated from the network.

## Initial Analysis

### Loading the PCAP

```bash
$ file challenge_traffic.pcap
challenge_traffic.pcap: pcap capture file, microsecond ts

$ capinfos challenge_traffic.pcap
File name:           challenge_traffic.pcap
Number of packets:   12
File size:           2.4 kB
Capture duration:    5 seconds
```

### Quick Overview with tshark

```bash
$ tshark -r challenge_traffic.pcap -q -z io,phs

 frame                                     12
   eth                                     12
     ip                                    12
       tcp                                  4
       udp                                  6
         dns                                6
       icmp                                2
```

Protocol breakdown:
- 4 TCP packets
- 6 UDP (DNS) packets
- 2 ICMP packets

---

## Part 1: HTTP Analysis

### Filtering HTTP Traffic

```bash
$ tshark -r challenge_traffic.pcap -Y "tcp.port == 80" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.payload

1   192.168.1.100   10.0.0.1   504f5354202f6c6f67696e...
```

### Extracting HTTP Content

```bash
$ tshark -r challenge_traffic.pcap -Y "tcp.port == 80" -T fields -e http.file_data

username=admin&password=s3cr3t!
```

Or follow TCP stream in Wireshark:
```
Right-click packet → Follow → TCP Stream
```

**Finding:** Credentials found in HTTP POST: `admin:s3cr3t!`

---

## Part 2: DNS Exfiltration

### Identifying Suspicious DNS Queries

```bash
$ tshark -r challenge_traffic.pcap -Y "dns" -T fields -e dns.qry.name

google.com
github.com
stackoverflow.com
irsw22dpmfsgc5lnnfwgkz3pmfxxeidb.exfil.attacker.com
irsw22dpmfsgc5lnnfwgkz3pmfxxeidb.exfil.attacker.com
...
```

The queries to `*.exfil.attacker.com` look suspicious!

### Extracting Suspicious Queries

```bash
$ tshark -r challenge_traffic.pcap -Y "dns.qry.name contains exfil" -T fields -e dns.qry.name

irsw22dpmfsgc5lnnfwgkz3pmfxxeidb.exfil.attacker.com
```

### Decoding the Data

The subdomain looks like Base32 encoding (uppercase letters and numbers 2-7):

```python
import base64

encoded = "irsw22dpmfsgc5lnnfwgkz3pmfxxeidb"
# Base32 decode (uppercase)
decoded = base64.b32decode(encoded.upper())
print(decoded.decode())
# Output: CTF{dns_3xf1ltr4t10n_d3t3ct3d}
```

**Flag:** `CTF{dns_3xf1ltr4t10n_d3t3ct3d}`

---

## Part 3: ICMP Tunneling

### Analyzing ICMP Traffic

```bash
$ tshark -r challenge_traffic.pcap -Y "icmp" -T fields -e frame.number -e ip.src -e ip.dst -e icmp.type -e data.len

5   192.168.1.100   10.0.0.1   8   45
...
```

ICMP echo request (type 8) with 45 bytes of data is unusual - normal ping is 64 bytes total.

### Extracting ICMP Payload

```bash
$ tshark -r challenge_traffic.pcap -Y "icmp" -T fields -e data

0000000000000000...435446...7b31636d705f...
```

Let's look at it more clearly:

```bash
$ tshark -r challenge_traffic.pcap -Y "icmp" -x

0050  00 00 00 00 00 00 00 00 43 54 46 7b 31 63 6d 70  ........CTF{1cmp
0060  5f 74 75 6e 6e 33 6c 5f 68 31 64 64 33 6e 5f 64  _tunn3l_h1dd3n_d
0070  34 74 34 7d 0a                                  4t4}.
```

The data after the 8 null bytes is the flag!

### Decoding

```python
payload_hex = "4354467b31636d705f74756e6e336c5f68316464336e5f643474347d"
payload = bytes.fromhex(payload_hex)
print(payload.decode())
# Output: CTF{1cmp_tunn3l_h1dd3n_d4t4}
```

**Flag:** `CTF{1cmp_tunn3l_h1dd3n_d4t4}`

---

## Part 4: TCP Options Analysis

### Examining TCP Handshake

```bash
$ tshark -r challenge_traffic.pcap -Y "tcp.flags.syn == 1" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.options
```

Looking at TCP options in Wireshark:
1. Expand TCP header in packet details
2. Look for unusual option types

### Finding the Hidden Option

TCP option kind 253 is experimental/unassigned:

```bash
$ tshark -r challenge_traffic.pcap -Y "tcp.options" -V | grep -A5 "Option"

Option Kind: 253 (Unknown)
Option Length: 32
Option Data: 5154467b7463705f30707431306e735f683164335f643174347d...
```

### Decoding the Option Data

```python
import base64

option_data_hex = "5154467b7463705f30707431306e735f683164335f643174347d"
option_data = bytes.fromhex(option_data_hex)
print(option_data.decode())
# This might be base64

decoded = base64.b64decode(option_data)
print(decoded.decode())
# Output: CTF{tcp_0pt10ns_h1d3_d4t4}
```

**Flag:** `CTF{tcp_0pt10ns_h1d3_d4t4}`

---

## Complete Solution Script

```python
#!/usr/bin/env python3
"""
Packet Analysis - Complete Solver
"""
from scapy.all import *
import base64

def analyze_http(packets):
    """Extract HTTP data"""
    print("[*] Analyzing HTTP traffic...")

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80:
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                print(f"    Found HTTP data: {payload[:100]}...")

                # Look for credentials
                if "password" in payload.lower():
                    lines = payload.split('\r\n')
                    for line in lines:
                        if "password" in line.lower():
                            print(f"    [!] Credential found: {line}")

def analyze_dns(packets):
    """Extract DNS exfiltration"""
    print("\n[*] Analyzing DNS traffic...")

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode()

            # Look for suspicious domains
            if "exfil" in qname or "attacker" in qname:
                # Extract subdomain
                subdomain = qname.split('.')[0]
                print(f"    Suspicious DNS query: {qname}")
                print(f"    Encoded data: {subdomain}")

                try:
                    # Try base32 decode
                    decoded = base64.b32decode(subdomain.upper())
                    print(f"    [+] Decoded: {decoded.decode()}")
                except:
                    pass

def analyze_icmp(packets):
    """Extract ICMP tunneling data"""
    print("\n[*] Analyzing ICMP traffic...")

    for pkt in packets:
        if pkt.haslayer(ICMP):
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load

                # Skip standard ICMP header (8 bytes)
                data = payload[8:]

                if b'CTF{' in data:
                    flag = data.decode().strip()
                    print(f"    [+] Found in ICMP payload: {flag}")

def analyze_tcp_options(packets):
    """Extract data from TCP options"""
    print("\n[*] Analyzing TCP options...")

    for pkt in packets:
        if pkt.haslayer(TCP):
            options = pkt[TCP].options

            for opt in options:
                # Check for unusual option types (253 is experimental)
                if opt[0] == 253 or (isinstance(opt, tuple) and len(opt) > 1):
                    try:
                        data = opt[1] if isinstance(opt[1], bytes) else bytes(opt[1])
                        if b'CTF' in data or b'QVF' in data:
                            try:
                                decoded = base64.b64decode(data)
                                print(f"    [+] Found in TCP options: {decoded.decode()}")
                            except:
                                print(f"    [+] Found in TCP options: {data}")
                    except:
                        pass

def main():
    print("=" * 60)
    print("Packet Analysis - Solver")
    print("=" * 60)

    # Load PCAP
    packets = rdpcap('challenge/challenge_traffic.pcap')
    print(f"\n[*] Loaded {len(packets)} packets\n")

    # Analyze each protocol
    analyze_http(packets)
    analyze_dns(packets)
    analyze_icmp(packets)
    analyze_tcp_options(packets)

    print("\n" + "=" * 60)
    print("Analysis Complete")
    print("=" * 60)

if __name__ == '__main__':
    main()
```

## Wireshark Filters Reference

| Purpose | Filter |
|---------|--------|
| HTTP traffic | `tcp.port == 80` |
| DNS queries | `dns.qry.name` |
| Suspicious DNS | `dns.qry.name contains "exfil"` |
| ICMP traffic | `icmp` |
| Large ICMP payloads | `icmp and data.len > 40` |
| TCP SYN packets | `tcp.flags.syn == 1` |
| Follow stream | Right-click → Follow → TCP Stream |

## Detection Techniques

### DNS Exfiltration Indicators
- Unusually long subdomain names
- Base32/Base64 encoded data in subdomains
- High frequency of unique subdomain queries
- Queries to suspicious TLDs

### ICMP Tunneling Indicators
- ICMP payloads larger than normal
- Non-printable characters in payload
- Unusual ICMP echo patterns
- Data after standard padding

### TCP Option Abuse
- Non-standard option types (>30)
- Unusually large option data
- Experimental/unassigned option codes

## Key Takeaways

1. **Many protocols can carry hidden data**
2. **DNS is commonly abused for exfiltration**
3. **ICMP is often overlooked in security monitoring**
4. **TCP options are rarely inspected**
5. **Base encoding is common for obfuscation**

## Tools Used

- **Wireshark** - GUI packet analysis
- **tshark** - Command-line packet analysis
- **scapy** - Python packet manipulation
- **NetworkMiner** - Automated extraction

---

*Network forensics requires understanding of protocols and attention to anomalies that indicate data hiding.*
