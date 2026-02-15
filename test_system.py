import unittest
from unittest.mock import MagicMock, patch
from services.groq_service import GroqService
from prompts import PromptManager

class TestDefendDetect(unittest.TestCase):

    def setUp(self):
        self.service = GroqService()
        
    @patch('services.groq_service.Groq')
    def test_phishing_flow(self, mock_groq):
        # Setup Mock
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices[0].message.content = "Analysis: Phishing Detected"
        mock_response.model = "llama-3.3-70b-versatile"
        mock_client.chat.completions.create.return_value = mock_response
        
        # Inject mock client into singleton
        self.service._client = mock_client
        
        # Test Prompt Formatting with Context
        subject = "Urgent Prize"
        body = "Click here to win"
        hf_mock = {"status": "success", "label": "Phishing", "score": 0.99}
        
        user_prompt = PromptManager.format_phishing_prompt(subject, body, hf_mock)
        self.assertIn("Urgent Prize", user_prompt)
        self.assertIn("AI Classification: Phishing", user_prompt)
        
        # Test Execution
        result = self.service.execute_prompt(user_prompt) 
        self.assertEqual(result["status"], "success")

    def test_url_context(self):
        url = "http://bad.com"
        vt_mock = {"status": "success", "stats": {"malicious": 5, "suspicious": 1, "harmless": 80}}
        hf_mock = {"status": "success", "label": "Malicious", "score": 0.95}
        
        prompt = PromptManager.format_url_prompt(url, vt_mock, hf_mock)
        self.assertIn("VirusTotal Analysis: 5/86", prompt)
        self.assertIn("AI Model Prediction: Malicious", prompt)

    def test_cve_context(self):
        cve = "CVE-2021-1234"
        nvd_mock = {"status": "success", "description": "Buffer overflow", "score": 9.8, "severity": "CRITICAL"}
        
        prompt = PromptManager.format_cve_prompt(cve, nvd_mock)
        self.assertIn("Official Description:\n        Buffer overflow", prompt)
        self.assertIn("CVSS Score: 9.8 (CRITICAL)", prompt)

    def test_input_sanitization(self):
        dirty_input = "   clean me   "
        clean = PromptManager.sanitize_input(dirty_input)
        self.assertEqual(clean, "clean me")
        
        long_input = "a" * 5000
        truncated = PromptManager.sanitize_input(long_input)
        self.assertTrue(len(truncated) <= 4050)
        self.assertTrue(truncated.endswith("...(truncated)"))

if __name__ == '__main__':
    unittest.main()
