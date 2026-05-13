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

    @staticmethod
    def calculate_file_entropy(file_bytes: bytes):
        """Calculate Shannon Entropy for a raw file to detect packing/encryption."""
        if not file_bytes:
            return 0
        
        entropy = 0
        file_len = len(file_bytes)
        
        # Calculate frequency of each byte
        byte_counts = [0] * 256
        for byte in file_bytes:
            byte_counts[byte] += 1
            
        for count in byte_counts:
            if count == 0:
                continue
            p = float(count) / file_len
            entropy -= p * math.log(p, 2)
            
        return round(entropy, 2)

    @staticmethod
    def analyze_pdf(file_bytes: bytes):
        """Analyze PDF for suspicious elements (JavaScript, OpenAction) without executing."""
        try:
            import PyPDF2
            import io
            
            pdf_file = io.BytesIO(file_bytes)
            reader = PyPDF2.PdfReader(pdf_file)
            
            suspicious_flags = []
            
            # Check for JavaScript in the catalog
            if reader.trailer and "/Root" in reader.trailer:
                root = reader.trailer["/Root"].get_object()
                if "/Names" in root and "/JavaScript" in root["/Names"]:
                    suspicious_flags.append("Embedded JavaScript found in catalog.")
                if "/OpenAction" in root:
                    suspicious_flags.append("Auto-launch action (/OpenAction) detected.")
                    
            # Basic page inspection for JS
            js_count = 0
            for page in reader.pages:
                if "/AA" in page or "/JavaScript" in page:
                     js_count += 1
            if js_count > 0:
                suspicious_flags.append(f"JavaScript found on {js_count} page(s).")
                
            return {
                "status": "success",
                "is_suspicious": len(suspicious_flags) > 0,
                "flags": suspicious_flags,
                "pages": len(reader.pages)
            }
        except ImportError:
            return {"status": "error", "message": "PyPDF2 not installed. Run 'pip install PyPDF2'."}
        except Exception as e:
            return {"status": "error", "message": f"PDF parse error: {str(e)}"}

    @staticmethod
    def check_pwned_password(password: str) -> dict:
        """
        Check if a password has been exposed using the HaveIBeenPwned API (k-Anonymity).
        Only sends the first 5 characters of the SHA-1 hash to the API.
        """
        import hashlib
        
        # 1. SHA-1 hash the password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # 2. Query HIBP API with only the prefix
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return {"status": "error", "message": f"HIBP API error: {response.status_code}"}
                
            # 3. Check if our suffix is in the returned list
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return {
                        "status": "success",
                        "pwned": True,
                        "count": int(count),
                        "hash_prefix": prefix
                    }
                    
            return {
                "status": "success",
                "pwned": False,
                "count": 0,
                "hash_prefix": prefix
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @staticmethod
    def simulate_email_breach(email: str) -> dict:
        """
        Since HIBP Email API is paid, we use a simulation/mock for educational purposes.
        If the email contains 'pwned', we simulate a breach. Otherwise, safe.
        """
        import time
        time.sleep(1.5) # Simulate API latency
        
        if "pwned" in email.lower() or "test" in email.lower():
            return {
                "status": "success",
                "breached": True,
                "breaches": [
                    {
                        "Name": "LinkedIn",
                        "Title": "LinkedIn 2012 Breach",
                        "Domain": "linkedin.com",
                        "BreachDate": "2012-05-05",
                        "DataClasses": ["Email addresses", "Passwords"]
                    },
                    {
                        "Name": "Canva",
                        "Title": "Canva",
                        "Domain": "canva.com",
                        "BreachDate": "2019-05-24",
                        "DataClasses": ["Email addresses", "Passwords", "Usernames", "Geographic locations"]
                    }
                ]
            }
            
        return {
            "status": "success",
            "breached": False,
            "breaches": []
        }
