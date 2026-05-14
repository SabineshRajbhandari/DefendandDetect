import requests
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ThreatIntelService:
    """
    Advanced Threat Intelligence Service for CISA KEV and EPSS scores.
    """
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    
    _cisa_cache = None
    _cisa_expiry = None

    @classmethod
    def _refresh_cisa_cache(cls):
        """Fetches and caches the CISA KEV catalog."""
        if cls._cisa_cache and cls._cisa_expiry and datetime.now() < cls._cisa_expiry:
            return

        try:
            response = requests.get(cls.CISA_KEV_URL, timeout=15)
            if response.status_code == 200:
                data = response.json()
                # Create a set of CVE IDs for O(1) lookup
                cls._cisa_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
                cls._cisa_expiry = datetime.now() + timedelta(hours=12)
                logger.info("CISA KEV Cache Refreshed.")
        except Exception as e:
            logger.error(f"Failed to refresh CISA KEV: {e}")
            cls._cisa_cache = cls._cisa_cache or {}

    @classmethod
    def check_cisa_kev(cls, cve_id: str) -> Dict[str, Any]:
        """Checks if a CVE is in the CISA Known Exploited Vulnerabilities catalog."""
        cls._refresh_cisa_cache()
        if cve_id in cls._cisa_cache:
            return {
                "is_exploited": True,
                "details": cls._cisa_cache[cve_id]
            }
        return {"is_exploited": False}

    @staticmethod
    def fetch_epss_score(cve_id: str) -> Dict[str, Any]:
        """Fetches the EPSS score from FIRST.org."""
        try:
            params = {"cve": cve_id}
            response = requests.get(ThreatIntelService.EPSS_API_URL, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if "data" in data and len(data["data"]) > 0:
                    item = data["data"][0]
                    return {
                        "status": "success",
                        "epss": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0))
                    }
        except Exception as e:
            logger.error(f"EPSS API Error: {e}")
        
        return {"status": "error", "epss": 0.0, "percentile": 0.0}

threat_intel_service = ThreatIntelService()
