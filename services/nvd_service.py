import requests
import logging
from typing import Dict, Any
from config import Config

logger = logging.getLogger(__name__)

class NVDService:
    """
    Service for finding vulnerability data from the National Vulnerability Database (NIST).
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @staticmethod
    def fetch_cve(cve_id: str) -> Dict[str, Any]:
        """
        Fetch details for a specific CVE ID.
        """
        api_key = Config.get_nvd_api_key()
        headers = {}
        if api_key:
            headers["apiKey"] = api_key
            
        params = {"cveId": cve_id}
        
        try:
            response = requests.get(NVDService.BASE_URL, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
                    cve_item = data["vulnerabilities"][0]["cve"]
                    
                    # Extract description
                    descriptions = cve_item.get("descriptions", [])
                    desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description found.")
                    
                    # Extract Metrics (CVSS)
                    metrics = cve_item.get("metrics", {})
                    score = "N/A"
                    severity = "Unknown"
                    
                    # Try V3.1, then V3.0, then V2
                    if "cvssMetricV31" in metrics:
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                    elif "cvssMetricV30" in metrics:
                         score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                         severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
                    
                    return {
                        "status": "success",
                        "id": cve_item["id"],
                        "description": desc_text,
                        "score": score,
                        "severity": severity,
                        "published": cve_item.get("published", ""),
                        "lastModified": cve_item.get("lastModified", "")
                    }
                else:
                    return {"status": "not_found", "error": "CVE ID not found in database."}
            elif response.status_code == 403:
                return {"status": "error", "error": "NVD API Key invalid or rate limit exceeded."}
            else:
                return {"status": "error", "error": f"API Error {response.status_code}"}
                
        except Exception as e:
            logger.error(f"NVD API Error: {e}")
            return {"status": "error", "error": str(e)}

nvd_service = NVDService()
