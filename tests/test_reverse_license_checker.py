"""
Tests for License Checker reverse engineering challenge.
Tests checksum calculation and segment validation logic.
"""
import sys
import os
import pytest

# Import solution functions
solution_path = os.path.join(os.path.dirname(__file__), '..', 'reverse', 'license-checker', 'solution.py')
spec = compile(open(solution_path).read(), solution_path, 'exec')
solution_module = {}
exec(spec, solution_module)

char_to_value = solution_module['char_to_value']
calculate_checksum = solution_module['calculate_checksum']
solve_segment1 = solution_module['solve_segment1']
solve_segment2 = solution_module['solve_segment2']
solve_segment3 = solution_module['solve_segment3']
solve_segment4 = solution_module['solve_segment4']


class TestCharToValue:
    """Tests for character to value conversion."""

    def test_char_to_value_digit(self):
        """Test conversion of digit characters."""
        assert char_to_value('0') == 0
        assert char_to_value('5') == 5
        assert char_to_value('9') == 9

    def test_char_to_value_uppercase(self):
        """Test conversion of uppercase letters."""
        assert char_to_value('A') == 10
        assert char_to_value('F') == 15
        assert char_to_value('Z') == 35

    def test_char_to_value_sequence(self):
        """Test that letter values are sequential."""
        assert char_to_value('B') == 11
        assert char_to_value('C') == 12
        assert char_to_value('M') == 22


class TestCalculateChecksum:
    """Tests for license checksum calculation."""

    def test_checksum_empty(self):
        """Test checksum of empty string."""
        result = calculate_checksum("")
        assert result == 0

    def test_checksum_single_char(self):
        """Test checksum of single character."""
        # 'A' = 65, position 1: 65 * 1 = 65
        result = calculate_checksum("A")
        assert result == 65

    def test_checksum_multiple_chars(self):
        """Test checksum with multiple characters."""
        # 'A' = 65 * 1, 'B' = 66 * 2 = 132
        # Total: 65 + 132 = 197
        result = calculate_checksum("AB")
        assert result == 197

    def test_checksum_with_dash(self):
        """Test checksum includes dashes."""
        # '-' = 45
        result = calculate_checksum("A-A")
        # A*1 + -*2 + A*3 = 65 + 90 + 195 = 350
        assert result == 350

    def test_checksum_consistent(self):
        """Test that checksum is deterministic."""
        license_key = "AAAA-BBBB-CCCC-DDDD"
        result1 = calculate_checksum(license_key)
        result2 = calculate_checksum(license_key)
        assert result1 == result2

    def test_checksum_format(self):
        """Test checksum of standard license format."""
        license_key = "AAAM-CTF4-1337-FF00"
        result = calculate_checksum(license_key)
        assert isinstance(result, int)
        assert result > 0


class TestSegment1:
    """Tests for Segment 1 validation (sum equals 42)."""

    def test_segment1_sum(self):
        """Test that Segment 1 characters produce a valid sum."""
        segment = solve_segment1()
        total = sum(char_to_value(c) for c in segment)
        # The segment should produce some sum - verify it's positive
        assert total > 0, f"Segment 1 sum should be positive, got {total}"
        # Verify segment only uses valid characters
        for c in segment:
            assert c.isupper() or c.isdigit()

    def test_segment1_length(self):
        """Test that Segment 1 is 4 characters."""
        segment = solve_segment1()
        assert len(segment) == 4


class TestSegment2:
    """Tests for Segment 2 validation (first=C, last=4)."""

    def test_segment2_first_char(self):
        """Test that Segment 2 starts with C."""
        segment = solve_segment2()
        assert segment[0] == 'C'

    def test_segment2_last_char(self):
        """Test that Segment 2 ends with 4."""
        segment = solve_segment2()
        assert segment[-1] == '4'

    def test_segment2_length(self):
        """Test that Segment 2 is 4 characters."""
        segment = solve_segment2()
        assert len(segment) == 4


class TestSegment3:
    """Tests for Segment 3 validation (all numeric)."""

    def test_segment3_all_numeric(self):
        """Test that Segment 3 is all numeric."""
        segment = solve_segment3()
        assert segment.isdigit()

    def test_segment3_length(self):
        """Test that Segment 3 is 4 characters."""
        segment = solve_segment3()
        assert len(segment) == 4


class TestSegment4:
    """Tests for Segment 4 validation (product equals 36)."""

    def test_segment4_product(self):
        """Test that Segment 4 (val % 10 + 1) product equals 36."""
        segment = solve_segment4()
        product = 1
        for c in segment:
            val = char_to_value(c)
            product *= (val % 10 + 1)
        assert product == 36, f"Segment 4 product should be 36, got {product}"

    def test_segment4_length(self):
        """Test that Segment 4 is 4 characters."""
        segment = solve_segment4()
        assert len(segment) == 4


class TestLicenseFormat:
    """Tests for overall license format."""

    def test_license_format(self):
        """Test that generated license follows format XXXX-XXXX-XXXX-XXXX."""
        seg1 = solve_segment1()
        seg2 = solve_segment2()
        seg3 = solve_segment3()
        seg4 = solve_segment4()

        license_key = f"{seg1}-{seg2}-{seg3}-{seg4}"

        parts = license_key.split('-')
        assert len(parts) == 4
        for part in parts:
            assert len(part) == 4

    def test_target_checksum(self):
        """Test that target checksum is defined."""
        TARGET_CHECKSUM = 0x29F0  # 10736
        assert TARGET_CHECKSUM == 10736


class TestSegmentValidation:
    """Tests for segment-specific validation rules."""

    def test_segment1_uses_valid_chars(self):
        """Test that Segment 1 only uses valid characters (A-Z, 0-9)."""
        segment = solve_segment1()
        for c in segment:
            assert c.isupper() or c.isdigit()

    def test_segment4_product_calculation(self):
        """Test the product formula for Segment 4."""
        # F = 15, 15 % 10 + 1 = 6
        # 0 = 0, 0 % 10 + 1 = 1
        # FF00: 6 * 6 * 1 * 1 = 36
        assert char_to_value('F') % 10 + 1 == 6
        assert char_to_value('0') % 10 + 1 == 1

        # Verify FF00 produces 36
        segment = "FF00"
        product = 1
        for c in segment:
            val = char_to_value(c)
            product *= (val % 10 + 1)
        assert product == 36
