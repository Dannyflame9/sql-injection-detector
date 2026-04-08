#!/usr/bin/env python3
"""
Unit tests for SQL Injection Scanner
Author: Olanite Daniel Pelumi
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector.scanner import SQLiScanner


class TestSQLiScanner(unittest.TestCase):
    """Test cases for SQLiScanner class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_url = "http://testphp.vulnweb.com/artists.php?artist=1"
        self.scanner = SQLiScanner(self.test_url, "artist", "GET")
    
    def test_init(self):
        """Test scanner initialization."""
        self.assertEqual(self.scanner.target_url, self.test_url)
        self.assertEqual(self.scanner.parameter, "artist")
        self.assertEqual(self.scanner.method, "GET")
        self.assertFalse(self.scanner.vulnerable)
        self.assertEqual(len(self.scanner.results), 0)
    
    def test_payloads_loaded(self):
        """Test that payloads are loaded correctly."""
        self.assertIn('error_based', self.scanner.payloads)
        self.assertIn('time_based', self.scanner.payloads)
        self.assertIn('union_based', self.scanner.payloads)
        self.assertGreater(len(self.scanner.payloads['error_based']), 0)
    
    def test_error_signatures_loaded(self):
        """Test that error signatures are loaded."""
        self.assertGreater(len(self.scanner.error_signatures), 0)
        self.assertIn("sql syntax", self.scanner.error_signatures)
    
    def test_scan_structure(self):
        """Test scan returns correct structure."""
        # Note: This makes real HTTP request
        # Use mock in production testing
        result = self.scanner.scan()
        
        self.assertIn('target', result)
        self.assertIn('parameter', result)
        self.assertIn('method', result)
        self.assertIn('scan_time', result)
        self.assertIn('vulnerable', result)
        self.assertIn('findings', result)
        self.assertIn('total_payloads_tested', result)
        
        self.assertEqual(result['target'], self.test_url)
        self.assertEqual(result['parameter'], "artist")
        self.assertIsInstance(result['vulnerable'], bool)
        self.assertIsInstance(result['findings'], list)
    
    def test_method_uppercase(self):
        """Test that method is converted to uppercase."""
        scanner = SQLiScanner(self.test_url, "id", "post")
        self.assertEqual(scanner.method, "POST")


class TestSQLiScannerEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""
    
    def test_invalid_url(self):
        """Test scanner handles invalid URLs gracefully."""
        scanner = SQLiScanner("not-a-valid-url", "id", "GET")
        result = scanner.scan()
        # Should complete without crashing
        self.assertIn('findings', result)
    
    def test_empty_parameter(self):
        """Test scanner with empty parameter name."""
        scanner = SQLiScanner("http://example.com", "", "GET")
        self.assertEqual(scanner.parameter, "")
    
    def test_special_characters_in_payload(self):
        """Test payloads with special characters."""
        scanner = SQLiScanner("http://example.com", "id", "GET")
        # Should handle special characters without crashing
        self.assertIn("'", str(scanner.payloads['error_based']))


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
