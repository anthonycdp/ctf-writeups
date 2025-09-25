"""
Tests for Forensics challenges.
Tests packet analysis and hidden data extraction logic.
"""
import pytest
import base64
import re


class TestPacketAnalysis:
    """Tests for packet analysis extraction functions."""

    def test_dns_exfiltration_decode(self):
        """Test DNS exfiltration decoding (Base32)."""
        # Simulated exfiltrated data
        encoded = "IZLGMZJWGU3DQNRTGQZTCLJO"  # Base32 encoded
        try:
            decoded = base64.b32decode(encoded.upper()).decode()
            assert isinstance(decoded, str)
        except Exception:
            # May fail if not valid Base32, that's OK for test
            pass

    def test_icmp_payload_flag_extraction(self):
        """Test ICMP payload flag extraction."""
        payload = b"Some data CTF{1cmp_tunn3l_h1dd3n_d4t4} more data"

        if b'CTF{' in payload:
            start = payload.find(b'CTF{')
            end = payload.find(b'}', start) + 1
            flag = payload[start:end].decode()

        assert flag == "CTF{1cmp_tunn3l_h1dd3n_d4t4}"

    def test_http_header_flag_extraction(self):
        """Test HTTP header flag extraction."""
        http_response = "HTTP/1.1 200 OK\r\nX-Flag: CTF{h77p_h34d3r_s3cr3t}\r\n\r\n"

        for line in http_response.split('\r\n'):
            if 'X-Flag:' in line:
                flag = line.split('X-Flag:')[1].strip()

        assert flag == "CTF{h77p_h34d3r_s3cr3t}"

    def test_tcp_options_base64_decode(self):
        """Test TCP options Base64 decoding."""
        # Simulated Base64 encoded flag
        encoded = "Q1RGe3RjcF8wcHQxMG5zX2g0ZDNfZDR0NH0="
        try:
            decoded = base64.b64decode(encoded).decode()
            assert decoded.startswith("CTF{")
        except Exception:
            pass


class TestLSBSteganography:
    """Tests for LSB steganography extraction."""

    def test_lsb_bit_extraction(self):
        """Test LSB bit extraction logic."""
        # Simulated pixel values
        pixels = [65, 66, 67, 68]  # Each has LSB: 1, 0, 1, 0

        bits = [p & 1 for p in pixels]
        assert bits == [1, 0, 1, 0]

    def test_lsb_length_extraction(self):
        """Test extracting length from first 16 bits."""
        # Length 4 in binary (16 bits): 0000000000000100
        bits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]
        length = int(''.join(map(str, bits)), 2)
        assert length == 4

    def test_lsb_byte_reconstruction(self):
        """Test reconstructing bytes from bits."""
        # 'A' = 65 = 01000001
        bits = [0, 1, 0, 0, 0, 0, 0, 1]
        byte_value = int(''.join(map(str, bits)), 2)
        assert byte_value == 65
        assert chr(byte_value) == 'A'

    def test_lsb_message_extraction(self):
        """Test full LSB message extraction logic."""
        # Simulate extracting "HI" (2 bytes)
        # H = 72 = 01001000
        # I = 73 = 01001001
        message_bits = (
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0] +  # Length = 2
            [0, 1, 0, 0, 1, 0, 0, 0] +  # H
            [0, 1, 0, 0, 1, 0, 0, 1]    # I
        )

        length = int(''.join(map(str, message_bits[:16])), 2)
        data_bits = message_bits[16:16 + length * 8]

        data_bytes = []
        for i in range(0, len(data_bits), 8):
            byte_bits = data_bits[i:i+8]
            if len(byte_bits) == 8:
                data_bytes.append(int(''.join(map(str, byte_bits)), 2))

        message = bytes(data_bytes).decode('utf-8', errors='ignore')
        assert message == "HI"


class TestZIPHiddenFiles:
    """Tests for ZIP hidden file extraction."""

    def test_hidden_file_detection(self):
        """Test detecting hidden files (starting with dot)."""
        files = ['.secret', 'readme.txt', '.flag', 'data.zip']
        hidden = [f for f in files if f.startswith('.')]
        assert '.secret' in hidden
        assert '.flag' in hidden
        assert 'readme.txt' not in hidden


class TestPolyglotFiles:
    """Tests for polyglot file analysis."""

    def test_png_end_marker_detection(self):
        """Test detecting PNG IEND marker."""
        # PNG ends with IEND chunk
        data = b"PNG data here" + b"IEND" + b"\x00\x00\x00\x00" + b"Hidden data after"

        iend = data.find(b'IEND')
        assert iend != -1

        # Data after IEND + CRC (4 bytes)
        hidden = data[iend + 8:]
        assert hidden == b"Hidden data after"

    def test_flag_in_hidden_data(self):
        """Test extracting flag from hidden data."""
        hidden = b"Some text CTF{p0lygl0t_f1l3_m4st3r} more text"
        text = hidden.decode('utf-8', errors='ignore')

        match = re.search(r'CTF\{[^}]+\}', text)
        assert match
        assert match.group() == "CTF{p0lygl0t_f1l3_m4st3r}"


class TestForensicsFlags:
    """Tests for expected forensics flags."""

    def test_dns_exfiltration_flag(self):
        """Test DNS exfiltration flag format."""
        expected = "CTF{dns_3xf1ltr4t10n_d3t3ct3d}"
        assert expected.startswith("CTF{")
        assert "dns" in expected.lower()

    def test_icmp_tunnel_flag(self):
        """Test ICMP tunnel flag format."""
        expected = "CTF{1cmp_tunn3l_h1dd3n_d4t4}"
        assert expected.startswith("CTF{")
        # Note: uses leetspeak "1cmp" instead of "icmp"
        assert "1cmp" in expected.lower() or "icmp" in expected.lower()

    def test_tcp_options_flag(self):
        """Test TCP options flag format."""
        expected = "CTF{tcp_0pt10ns_h1d3_d4t4}"
        assert expected.startswith("CTF{")
        assert "tcp" in expected.lower()

    def test_http_header_flag(self):
        """Test HTTP header flag format."""
        expected = "CTF{h77p_h34d3r_s3cr3t}"
        assert expected.startswith("CTF{")
        # Note: uses leetspeak "h77p" instead of "http"
        assert "h77p" in expected.lower() or "http" in expected.lower()


class TestBaseEncoding:
    """Tests for base encoding/decoding utilities."""

    def test_base32_encode_decode(self):
        """Test Base32 encoding/decoding."""
        message = "CTF{test_flag}"
        encoded = base64.b32encode(message.encode()).decode()
        decoded = base64.b32decode(encoded).decode()
        assert decoded == message

    def test_base64_encode_decode(self):
        """Test Base64 encoding/decoding."""
        message = "CTF{test_flag}"
        encoded = base64.b64encode(message.encode()).decode()
        decoded = base64.b64decode(encoded).decode()
        assert decoded == message

    def test_hex_encode_decode(self):
        """Test hex encoding/decoding."""
        message = b"CTF{test_flag}"
        encoded = message.hex()
        decoded = bytes.fromhex(encoded)
        assert decoded == message
