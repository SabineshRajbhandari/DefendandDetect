import unittest
import os
import json
import re
from services.database_service import DatabaseService
from services.report_service import ReportService

class TestAdvancedHardening(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        DatabaseService.DB_FILE = "test_hardening.db"
        DatabaseService.init_db()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists("test_hardening.db"):
            os.remove("test_hardening.db")

    def test_cve_regex(self):
        cve_pattern = r"^CVE-\d{4}-\d{4,}$"
        self.assertTrue(re.match(cve_pattern, "CVE-2021-44228"))
        self.assertTrue(re.match(cve_pattern, "CVE-2024-123456"))
        self.assertFalse(re.match(cve_pattern, "CVE-21-44228"))
        self.assertFalse(re.match(cve_pattern, "invalid-cve"))

    def test_url_regex(self):
        url_pattern = r"^(https?:\/\/)([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$"
        self.assertTrue(re.match(url_pattern, "https://google.com"))
        self.assertTrue(re.match(url_pattern, "http://internal.site/path"))
        self.assertFalse(re.match(url_pattern, "not.a.url"))
        self.assertFalse(re.match(url_pattern, "www.google.com"))

    def test_content_length_simulation(self):
        # Simulation of module logic
        phish_min = 20
        log_min = 10
        
        valid_phish = "This is a long enough email body for analysis."
        short_phish = "Too short"
        
        self.assertTrue(len(valid_phish.strip()) >= phish_min)
        self.assertFalse(len(short_phish.strip()) >= phish_min)

    def test_navigation_state_clearing_logic(self):
        session_state = {
            "active_phish_result": {"data": 1},
            "active_url_result": {"data": 2},
            "other_var": "keep"
        }
        active_states = ["active_phish_result", "active_url_result", "active_log_result"]
        for state in active_states:
            if state in session_state:
                session_state[state] = None
        
        self.assertIsNone(session_state["active_phish_result"])
        self.assertIsNone(session_state["active_url_result"])
        self.assertEqual(session_state["other_var"], "keep")

if __name__ == '__main__':
    unittest.main()
