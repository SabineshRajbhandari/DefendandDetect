import whois
import yara
import re
import requests
import math
import socket
from datetime import datetime
import os

class IntelligenceService:
    @staticmethod
    def get_whois_data(url: str):
        """Fetch WHOIS registration data for a given URL."""
        try:
            domain_match = re.search(r'(?:https?://)?([^:/#?]+)', url)
            if not domain_match:
                return {"status": "error", "message": "Invalid URL format"}
            
            domain = domain_match.group(1)
            w = whois.whois(domain)
            
            def normalize_date(date):
                if isinstance(date, list):
                    return date[0]
                return date

            reg_date = normalize_date(w.creation_date)
            exp_date = normalize_date(w.expiration_date)
            
            domain_age_days = None
            if reg_date:
                domain_age_days = (datetime.now() - reg_date).days

            return {
                "status": "success",
                "domain": domain,
                "registrar": w.registrar,
                "org": w.org,
                "creation_date": reg_date.strftime('%Y-%m-%d') if reg_date else "Unknown",
                "expiration_date": exp_date.strftime('%Y-%m-%d') if exp_date else "Unknown",
                "age_days": domain_age_days,
                "is_new": domain_age_days < 30 if domain_age_days is not None else False
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @staticmethod
    def get_geo_info(url: str):
        """Resolve domain to IP and fetch Geolocation data."""
        try:
            domain_match = re.search(r'(?:https?://)?([^:/#?]+)', url)
            if not domain_match:
                return {"status": "error", "message": "Invalid URL"}
            
            domain = domain_match.group(1)
            ip_addr = socket.gethostbyname(domain)
            
            # Use ip-api.com (Free for non-commercial, no key required)
            response = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=5)
            data = response.json()
            
            if data.get("status") == "success":
                return {
                    "status": "success",
                    "ip": ip_addr,
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as")
                }
            return {"status": "error", "message": "Geo lookup failed"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @staticmethod
    def get_redirect_chain(url: str):
        """Follow redirects and map the behavioral chain."""
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            chain = [r.url for r in response.history]
            chain.append(response.url) # Final URL
            
            return {
                "status": "success",
                "chain": chain,
                "depth": len(chain) - 1,
                "final_url": response.url,
                "is_redirected": len(chain) > 1
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @staticmethod
    def calculate_entropy(text: str):
        """Calculate Shannon Entropy to detect DGA/Random domains."""
        if not text:
            return 0
        
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return round(entropy, 2)

    @staticmethod
    def check_lookalike(domain: str):
        """Basic detection for lookalike/homograph domains."""
        top_domains = ["google", "microsoft", "apple", "amazon", "facebook", "netflix", "paypal", "bankofamerica"]
        domain_clean = domain.split('.')[0].lower()
        
        from difflib import SequenceMatcher
        for top in top_domains:
            ratio = SequenceMatcher(None, domain_clean, top).ratio()
            if 0.8 <= ratio < 1.0: # High similarity but not exact
                return {"status": "warning", "match": top.title(), "score": round(ratio, 2)}
        
        return {"status": "clear"}

    @staticmethod
    def scan_yara(text: str, rules_path: str = "rules/phishing.yar"):
        """Scan text using local YARA rules."""
        if not os.path.exists(rules_path):
            return {"status": "error", "message": f"Rules file {rules_path} not found"}
        
        try:
            rules = yara.compile(rules_path)
            matches = rules.match(data=text)
            
            return {
                "status": "success",
                "matches": [m.rule for m in matches],
                "match_count": len(matches)
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
