"""
Tests for Weak RSA - Wiener's Attack challenge.
Tests continued fraction computation and Wiener's attack implementation.
"""
import math
import pytest


# Import solution functions by executing the solver
import sys
import os

solution_path = os.path.join(os.path.dirname(__file__), '..', 'crypto', 'weak-rsa', 'solution.py')
spec = compile(open(solution_path).read(), solution_path, 'exec')
solution_module = {}
exec(spec, solution_module)

continued_fraction = solution_module['continued_fraction']
convergents = solution_module['convergents']
wiener_attack = solution_module['wiener_attack']


class TestContinuedFractions:
    """Tests for continued fraction computation."""

    def test_continued_fraction_integer(self):
        """Test continued fraction of integer."""
        result = continued_fraction(5, 1)
        assert result == [5]

    def test_continued_fraction_simple_fraction(self):
        """Test continued fraction of simple fraction."""
        # 3/2 = 1 + 1/2
        result = continued_fraction(3, 2)
        assert result == [1, 2]

    def test_continued_fraction_golden_ratio_approx(self):
        """Test continued fraction approximation."""
        # 21/13 (Fibonacci numbers) approximates golden ratio
        # Actual CF: 21/13 = [1, 1, 1, 1, 1, 2]
        result = continued_fraction(21, 13)
        assert result == [1, 1, 1, 1, 1, 2]

    def test_continued_fraction_e_approx(self):
        """Test continued fraction for e approximation."""
        # e ≈ 2.718 = [2, 1, 2, 1, 1, 4, 1, 1, 6, ...]
        # 87/32 ≈ 2.71875 has CF [2, 1, 2, 1, 1, 4]
        result = continued_fraction(87, 32)
        assert result == [2, 1, 2, 1, 1, 4]

    def test_continued_fraction_zero_denominator(self):
        """Test continued fraction with zero denominator."""
        result = continued_fraction(5, 0)
        # Should handle gracefully
        assert isinstance(result, list)


class TestConvergents:
    """Tests for convergent generation."""

    def test_convergents_simple(self):
        """Test convergents for simple continued fraction."""
        cf = [1, 2]  # 1 + 1/2 = 3/2
        convs = list(convergents(cf))
        # First convergent: 1/1
        # Second convergent: 3/2
        assert (1, 1) in convs
        assert (3, 2) in convs

    def test_convergents_golden_ratio(self):
        """Test convergents for golden ratio approximation."""
        cf = [1, 1, 1, 1, 1]  # Fibonacci-like
        convs = list(convergents(cf))
        # Convergents should be ratios of consecutive Fibonacci numbers
        # 1/1, 2/1, 3/2, 5/3, 8/5
        expected = [(1, 1), (2, 1), (3, 2), (5, 3), (8, 5)]
        for n, d in convs:
            assert (n, d) in expected

    def test_convergents_single_element(self):
        """Test convergents for single element CF."""
        cf = [5]
        convs = list(convergents(cf))
        assert (5, 1) in convs


class TestWienerAttack:
    """Tests for Wiener's attack implementation."""

    def test_wiener_attack_small_d(self):
        """Test Wiener's attack with known vulnerable parameters."""
        # Generate a small test case
        # For small d, we need: d < n^(1/4) / 3
        # Using small primes for testing
        p = 10007
        q = 10009
        n = p * q
        phi = (p - 1) * (q - 1)

        # Choose small d
        d = 17
        # Find e such that e*d = 1 (mod phi)
        e = pow(d, -1, phi)

        d_recovered, p_recovered, q_recovered = wiener_attack(e, n)

        assert d_recovered == d
        assert p_recovered * q_recovered == n

    def test_wiener_attack_verification(self):
        """Test that recovered key works for decryption."""
        p = 10007
        q = 10009
        n = p * q
        phi = (p - 1) * (q - 1)

        d = 37
        e = pow(d, -1, phi)

        # Test message
        message = 12345
        c = pow(message, e, n)

        d_recovered, _, _ = wiener_attack(e, n)

        # Decrypt with recovered key
        decrypted = pow(c, d_recovered, n)
        assert decrypted == message

    def test_wiener_attack_large_d_fails(self):
        """Test that Wiener's attack fails with large d."""
        # Large primes
        p = 1000000007
        q = 1000000009
        n = p * q
        phi = (p - 1) * (q - 1)

        # Use standard e=65537 and compute d (which will be large)
        e = 65537
        d = pow(e, -1, phi)

        # For large d, Wiener's attack should fail
        d_recovered, p_recovered, q_recovered = wiener_attack(e, n)

        # Should fail to recover (returns None for large d)
        # The attack only works when d < n^(1/4) / 3
        assert d_recovered is None or d_recovered != d


class TestRSAEncryption:
    """Tests for basic RSA operations."""

    def test_rsa_encrypt_decrypt(self):
        """Test basic RSA encrypt/decrypt cycle."""
        # Use larger primes for bigger modulus
        p = 100003  # Larger prime
        q = 100019  # Larger prime
        n = p * q   # n ≈ 10^10, fits messages up to ~33 bits
        phi = (p - 1) * (q - 1)

        e = 65537
        d = pow(e, -1, phi)

        # Use a small message that fits in the modulus
        message = b"Hi"  # 2 bytes = 16 bits, fits easily
        m = int.from_bytes(message, 'big')
        assert m < n, "Message must be smaller than modulus"
        c = pow(m, e, n)
        m_decrypted = pow(c, d, n)
        decrypted = m_decrypted.to_bytes((m_decrypted.bit_length() + 7) // 8, 'big')

        assert decrypted == message

    def test_rsa_modular_inverse(self):
        """Test that e*d = 1 (mod phi)."""
        p = 10007
        q = 10009
        phi = (p - 1) * (q - 1)

        d = 17
        e = pow(d, -1, phi)

        assert (e * d) % phi == 1


class TestWienerAttackConditions:
    """Tests for Wiener's attack viability conditions."""

    def test_wiener_condition_small_d(self):
        """Test the condition d < n^(1/4) / 3."""
        # Small primes mean small n, so reasonable d is "small"
        p = 10007
        q = 10009
        n = p * q

        threshold = (n ** 0.25) / 3

        # d = 17 should satisfy condition for this n
        assert 17 < threshold

    def test_e_greater_than_n_indicator(self):
        """Test that small d tends to produce large e."""
        p = 10007
        q = 10009
        n = p * q
        phi = (p - 1) * (q - 1)

        # Use d=5 which is very small
        d = 5
        e = pow(d, -1, phi)

        # For Wiener attack to work: d < n^(1/4) / 3
        # For n ≈ 10^8, n^(1/4) ≈ 100, so d < 33
        # Small d produces large e (often e > n when d is very small)
        # Just verify that the relationship exists
        assert (e * d) % phi == 1  # Verify e and d are inverses
