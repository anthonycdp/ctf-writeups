"""
Pytest configuration and shared fixtures for CTF writeup tests.
"""
import sys
import os
import pytest

# Add project root to path for imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


# Expected flags for validation
EXPECTED_FLAGS = {
    "buffer_overflow_basics": "CTF{buff3r_0v3rfl0w_sh3llc0d3_m4st3r}",
    "weak_rsa": "CTF{w13n3r_4tt4ck_sm4ll_d_1s_d4ng3r0u5}",
    "sql_injection_101": "CTF{sql_1nj3ct10n_m4st3r_2024}",
    "xss_filter_bypass": "CTF{xss_f1lt3r_byp4ss3d_l1k3_4_pr0}",
    "license_checker": "CTF{r3v3rs3_3ng1n33r1ng_m4st3r}",
    "stack_overflow_101": "CTF{buff3r_0v3rfl0w_101_c0mpl3t3}",
    "dns_exfiltration": "CTF{dns_3xf1ltr4t10n_d3t3ct3d}",
    "icmp_tunnel": "CTF{1cmp_tunn3l_h1dd3n_d4t4}",
    "tcp_options": "CTF{tcp_0pt10ns_h1d3_d4t4}",
    "http_header": "CTF{h77p_h34d3r_s3cr3t}",
}


@pytest.fixture
def project_root():
    """Return the project root directory."""
    return PROJECT_ROOT


@pytest.fixture
def expected_flags():
    """Return dictionary of expected flags."""
    return EXPECTED_FLAGS.copy()
