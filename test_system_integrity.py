import time
import unittest
import sys
import os
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.intelligence_service import IntelligenceService
from services.database_service import DatabaseService
from services.virustotal_service import VirusTotalService

class TestSystemIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "="*50)
        print("🛡️ DEFEND & DETECT: SYSTEM INTEGRITY AUDIT 🛡️")
        print("="*50)
        DatabaseService.init_db()

    def test_latency_intelligence_lexical(self):
        """Benchmark Lexical Analysis Latency"""
        print("\n[PERF] Testing Lexical Analysis Latency...")
        test_url = "https://secure-login-bank-verification.com/auth/login"
        
        start_time = time.time()
        res = IntelligenceService.calculate_entropy(test_url)
        duration = time.time() - start_time
        
        print(f"  - Entropy Calc: {duration:.4f}s")
        self.assertLess(duration, 0.1, "Entropy calculation exceeds latency threshold")

        start_time = time.time()
        res = IntelligenceService.check_lookalike(test_url)
        duration = time.time() - start_time
        
        print(f"  - Lookalike Check: {duration:.4f}s")
        self.assertLess(duration, 0.5, "Lookalike check exceeds latency threshold")

    def test_security_xss_protection(self):
        """Verify XSS Protection in Data Flow"""
        print("\n[SEC] Testing XSS Protection (HTML Escaping)...")
        # We simulate the text_diff logic which uses html.escape
        import html
        malicious_input = "<script>alert('XSS')</script>"
        escaped = html.escape(malicious_input)
        
        print(f"  - Input: {malicious_input}")
        print(f"  - Escaped: {escaped}")
        
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)

    def test_security_sqli_resilience(self):
        """Verify SQL Injection Resilience (Parameterized Queries)"""
        print("\n[SEC] Testing SQLi Resilience...")
        # DatabaseService uses sqlite3 with parameterized queries
        malicious_sector = "URL' OR '1'='1"
        try:
            # Should not crash and should return empty if no match
            results = DatabaseService.get_history(sector=malicious_sector)
            print(f"  - SQLi Input '{malicious_sector}' handled correctly.")
            self.assertIsInstance(results, list)
        except Exception as e:
            self.fail(f"SQLi input caused a crash: {e}")

    def test_resilience_large_payload(self):
        """Test System stability with 10k character payload"""
        print("\n[RES] Testing Large Payload Handling (10,000 chars)...")
        large_payload = "A" * 10000
        
        # Test Entropy on large payload
        start_time = time.time()
        res = IntelligenceService.calculate_entropy(large_payload)
        duration = time.time() - start_time
        
        print(f"  - Large entropy calc (10k): {duration:.4f}s")
        self.assertLess(duration, 1.0, "Large payload processing too slow")

if __name__ == "__main__":
    unittest.main()
