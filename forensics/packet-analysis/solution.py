#!/usr/bin/env python3
"""
Packet Analysis - Solution Script
Extracts hidden flags from PCAP files using various techniques
"""

import os
import base64
import sys

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] scapy not installed. Install with: pip install scapy")
    print("[!] Some features will be limited.")


def extract_dns_exfiltration(pcap_file):
    """
    Extract data exfiltrated via DNS queries
    Look for Base32 encoded subdomains
    """
    if not SCAPY_AVAILABLE:
        print("[-] Scapy required for DNS extraction")
        return []

    packets = rdpcap(pcap_file)
    encoded_chunks = []
    flags_found = []

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname

            # Look for suspicious subdomains (exfil patterns)
            if 'exfil' in qname.lower() or 'attacker' in qname.lower():
                # Extract the subdomain part
                parts = qname.split('.')
                if parts:
                    encoded_chunks.append(parts[0])

    # Try to decode
    if encoded_chunks:
        try:
            combined = ''.join(encoded_chunks)
            # Try Base32 decode
            decoded = base64.b32decode(combined.upper()).decode()
            print(f"[+] DNS Exfiltration decoded: {decoded}")
            flags_found.append(decoded)
        except Exception as e:
            print(f"[-] Could not decode DNS data: {e}")

    return flags_found


def extract_icmp_payload(pcap_file):
    """
    Extract hidden data from ICMP packet payloads
    """
    if not SCAPY_AVAILABLE:
        print("[-] Scapy required for ICMP extraction")
        return []

    packets = rdpcap(pcap_file)
    flags_found = []

    for pkt in packets:
        if pkt.haslayer(ICMP):
            # Check for data in ICMP payload
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)

                # Look for flag patterns
                if b'CTF{' in payload:
                    start = payload.find(b'CTF{')
                    end = payload.find(b'}', start) + 1
                    flag = payload[start:end].decode()
                    print(f"[+] ICMP payload found: {flag}")
                    flags_found.append(flag)

    return flags_found


def extract_tcp_options(pcap_file):
    """
    Extract hidden data from TCP options
    """
    if not SCAPY_AVAILABLE:
        print("[-] Scapy required for TCP options extraction")
        return []

    packets = rdpcap(pcap_file)
    flags_found = []

    for pkt in packets:
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]

            # Check for experimental options (kind 253, etc.)
            if hasattr(tcp_layer, 'options'):
                for opt_kind, opt_value in tcp_layer.options:
                    if opt_kind >= 250 and opt_value:  # Experimental options
                        try:
                            # Try base64 decode
                            decoded = base64.b64decode(opt_value).decode()
                            if 'CTF{' in decoded:
                                print(f"[+] TCP option found: {decoded}")
                                flags_found.append(decoded)
                        except:
                            pass

    return flags_found


def extract_http_headers(pcap_file):
    """
    Extract data from HTTP headers
    """
    if not SCAPY_AVAILABLE:
        print("[-] Scapy required for HTTP extraction")
        return []

    packets = rdpcap(pcap_file)
    flags_found = []

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load).decode('utf-8', errors='ignore')

                # Look for HTTP headers with flags
                if 'X-Flag:' in payload:
                    for line in payload.split('\r\n'):
                        if 'X-Flag:' in line:
                            flag = line.split('X-Flag:')[1].strip()
                            print(f"[+] HTTP header found: {flag}")
                            flags_found.append(flag)
            except:
                pass

    return flags_found


def analyze_pcap(pcap_file):
    """
    Comprehensive PCAP analysis
    """
    if not os.path.exists(pcap_file):
        print(f"[-] PCAP file not found: {pcap_file}")
        print("[*] Creating challenge PCAP first...")
        os.chdir('challenge')
        os.system('python3 create_pcap.py')
        os.chdir('..')

        if not os.path.exists(pcap_file):
            print("[-] Could not create PCAP. Check scapy installation.")
            return []

    print(f"[*] Analyzing: {pcap_file}")
    print("=" * 50)

    all_flags = []

    # Run all extraction methods
    print("\n[*] Checking DNS exfiltration...")
    all_flags.extend(extract_dns_exfiltration(pcap_file))

    print("\n[*] Checking ICMP payloads...")
    all_flags.extend(extract_icmp_payload(pcap_file))

    print("\n[*] Checking TCP options...")
    all_flags.extend(extract_tcp_options(pcap_file))

    print("\n[*] Checking HTTP headers...")
    all_flags.extend(extract_http_headers(pcap_file))

    return all_flags


def tshark_analysis(pcap_file):
    """
    Alternative analysis using tshark if available
    """
    print("\n[*] Tshark-based analysis tips:")
    print("=" * 50)
    print("  # View DNS queries:")
    print(f"  tshark -r {pcap_file} -Y 'dns' -T fields -e dns.qry.name")
    print("")
    print("  # View ICMP payloads:")
    print(f"  tshark -r {pcap_file} -Y 'icmp' -x")
    print("")
    print("  # View HTTP traffic:")
    print(f"  tshark -r {pcap_file} -Y 'http' -T fields -e http.file_data")
    print("")
    print("  # Follow TCP streams:")
    print(f"  tshark -r {pcap_file} -q -z follow,tcp,ascii,0")


def main():
    print("=" * 60)
    print("Packet Analysis - Solution Script")
    print("=" * 60)

    # Determine which PCAP files to analyze
    pcap_files = [
        'challenge/challenge_traffic.pcap',
        'challenge/simple_traffic.pcap'
    ]

    all_flags = []

    for pcap in pcap_files:
        if os.path.exists(pcap):
            flags = analyze_pcap(pcap)
            all_flags.extend(flags)

    # Also try the simple PCAP
    if not any(os.path.exists(p) for p in pcap_files):
        print("\n[*] No PCAP files found. Creating them now...")
        os.chdir('challenge')
        try:
            import create_pcap
            create_pcap.create_challenge_pcap()
            create_pcap.create_simple_pcap()
        except ImportError:
            print("[-] Could not import create_pcap module")
        os.chdir('..')

        # Try again
        for pcap in pcap_files:
            if os.path.exists(pcap):
                flags = analyze_pcap(pcap)
                all_flags.extend(flags)

    # Show tshark tips
    tshark_analysis('challenge/challenge_traffic.pcap')

    # Summary
    print("\n" + "=" * 60)
    print("FLAGS FOUND:")
    print("=" * 60)

    if all_flags:
        for i, flag in enumerate(set(all_flags), 1):
            print(f"  {i}. {flag}")
    else:
        print("  No flags extracted. Expected flags:")
        print("  1. CTF{dns_3xf1ltr4t10n_d3t3ct3d}")
        print("  2. CTF{1cmp_tunn3l_h1dd3n_d4t4}")
        print("  3. CTF{tcp_0pt10ns_h1d3_d4t4}")
        print("  4. CTF{h77p_h34d3r_s3cr3t}")

    print("=" * 60)


if __name__ == '__main__':
    main()
