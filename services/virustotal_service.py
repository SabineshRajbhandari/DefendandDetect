import requests
import base64
from config import Config

class VirusTotalService:
    @staticmethod
    def get_url_id(url: str) -> str:
        """
        Base64 encode URL to get the VT ID.
        """
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    @staticmethod
    def check_url(url: str) -> dict:
        """
        Check URL reputation using VirusTotal API v3.
        """
        if not Config.get_virustotal_api_key():
            return {"status": "error", "message": "API Key Missing"}

        try:
            url_id = VirusTotalService.get_url_id(url)
            headers = {"x-apikey": Config.get_virustotal_api_key()}
            
            # GET /urls/{id}
            response = requests.get(
                f"{Config.VIRUSTOTAL_BASE_URL}/urls/{url_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                
                # Determine verdict based on malicious count
                is_malicious = stats.get("malicious", 0) > 0
                
                return {
                    "status": "success",
                    "is_malicious": is_malicious,
                    "stats": stats,
                    "scan_date": data["data"]["attributes"].get("last_analysis_date")
                }
            elif response.status_code == 404:
                return {"status": "success", "message": "URL not found in database (Clean or Unscanned)"}
            else:
                return {"status": "error", "message": f"API Error: {response.status_code}"}
                
        except Exception as e:
            return {"status": "error", "message": str(e)}
    @staticmethod
    def check_file_hash(file_hash: str) -> dict:
        """
        Check file reputation using VirusTotal API v3 based on SHA-256 hash.
        """
        if not Config.get_virustotal_api_key():
            return {"status": "error", "message": "API Key Missing"}

        try:
            headers = {"x-apikey": Config.get_virustotal_api_key()}
            
            # GET /files/{id}
            response = requests.get(
                f"{Config.VIRUSTOTAL_BASE_URL}/files/{file_hash}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                
                # Determine verdict based on malicious count
                is_malicious = stats.get("malicious", 0) > 0
                
                return {
                    "status": "success",
                    "is_malicious": is_malicious,
                    "stats": stats,
                    "scan_date": data["data"]["attributes"].get("last_analysis_date")
                }
            elif response.status_code == 404:
                return {"status": "success", "message": "Hash not found in database (Clean or Unscanned)"}
            else:
                return {"status": "error", "message": f"API Error: {response.status_code}"}
                
        except Exception as e:
            return {"status": "error", "message": str(e)}
