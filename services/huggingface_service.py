import requests
import logging
import time
from typing import Dict, Any, Optional
from config import Config

logger = logging.getLogger(__name__)

class HuggingFaceService:
    """
    Service for interacting with Hugging Face Inference API.
    Used for ML-based classification of phishing emails and malicious URLs.
    """
    
    API_URL = "https://router.huggingface.co/hf-inference/models/"

    @staticmethod
    def _query(payload: Dict[str, Any], model_id: str) -> Dict[str, Any]:
        api_key = Config.get_hf_api_key()
        if not api_key:
            return {"error": "HF API Key missing"}

        headers = {"Authorization": f"Bearer {api_key}"}
        url = f"{HuggingFaceService.API_URL}{model_id}"

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            return response.json()
        except Exception as e:
            logger.error(f"HF API Error: {e}")
            return {"error": str(e)}

    @staticmethod
    def classify_phishing(text: str) -> Dict[str, Any]:
        """
        Classify text using a phishing detection model.
        Returns label and score.
        """
        model = Config.HF_PHISHING_MODEL
        payload = {"inputs": text}
        
        result = HuggingFaceService._query(payload, model)
        
        # simple parsing logic for standard text-classification output
        # Output format usually: [[{'label': 'LABEL_0', 'score': 0.99}, ...]]
        if isinstance(result, list) and len(result) > 0 and isinstance(result[0], list):
            # Get top prediction
            top_pred = max(result[0], key=lambda x: x['score'])
            return {
                "status": "success",
                "label": top_pred['label'], # Often LABEL_0 (Safe) or LABEL_1 (Phishing) - varies by model
                "score": top_pred['score'],
                "raw": result
            }
        elif "error" in result:
             # Handle model loading state
            if "loading" in result.get("error", "").lower():
                 return {"status": "loading", "message": "Model is loading, please try again in 30s."}
            return {"status": "error", "error": result["error"]}
            
        return {"status": "error", "error": "Invalid response format"}

    @staticmethod
    def classify_url(url: str) -> Dict[str, Any]:
        """
        Classify a URL using a BERT-based URL model.
        """
        model = Config.HF_URL_MODEL
        payload = {"inputs": url}
        
        result = HuggingFaceService._query(payload, model)
        
        if isinstance(result, list) and len(result) > 0 and isinstance(result[0], list):
             top_pred = max(result[0], key=lambda x: x['score'])
             return {
                "status": "success",
                "label": top_pred['label'],
                "score": top_pred['score'],
                "raw": result
            }
            
        if "error" in result:
             return {"status": "error", "error": result["error"]}

        return {"status": "error", "error": "Unknown response"}

hf_service = HuggingFaceService()
