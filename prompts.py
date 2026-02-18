import re

class PromptManager:
    """
    Central repository for GROQ prompts.
    Ensures consistent system instructions and modular prompt construction.
    """

    SYSTEM_PROMPTS = {
        "phishing": """
You are a Cyber Security Analyst Expert specialized in social engineering and email threats.
Analyze the following email content.
Output your analysis in a structured format. 
FIRST, provide your internal reasoning process inside a <thought> block.
THEN, provide the following sections:
1. **Verdict**: (Safe / Suspicious / Malicious)
2. **Confidence Score**: (0-100%)
3. **Key Indicators**: Bullet points of specific suspicious elements (sender, links, urgency, grammar).
4. **Educational Explanation**: A brief lesson on why this is a threat, suitable for a beginner.
""",
        "url": """
You are a Threat Intelligence Specialist.
Analyze the following URL for malicious characteristics.
Do NOT access the URL. Analyze it based on string characteristics, obfuscation, and known patterns.
FIRST, provide your internal reasoning process inside a <thought> block.
THEN, provide the following sections:
1. **Risk Assessment**: (Low / Medium / High / Critical)
2. **Analysis**: Breakdown of the domain, path, and query parameters.
3. **Obfuscation Detection**: Mention any encoding, IP usage, or typosquatting.
4. **Safety Tip**: How users can spot this in the future.
""",
        "cve": """
You are a Vulnerability Management Instructor.
Explain the following CVE (Common Vulnerabilities and Exposures) entry to a junior IT student.
FIRST, provide your internal reasoning process inside a <thought> block.
THEN, provide the following sections:
1. **Plain English Summary**: What actually happens?
2. **Impact**: What can the attacker do? (RCE, DoS, Info Leak)
3. **Severity**: Explain the CVSS score context.
4. **Remediation**: General steps to fix or mitigate.
Keep the tone educational and clear.
""",
        "logs": """
You are a SOC (Security Operations Center) Analyst.
Translate the following raw log entry into a human-readable security alert.
FIRST, provide your internal reasoning process inside a <thought> block.
THEN, provide the following sections:
1. **Event Summary**: One sentence describing what happened.
2. **Threat Type**: (Brute Force, SQL Injection, Privilege Escalation, etc.)
3. **Source/Destination**: Extract IPs or Users if present.
4. **Action Required**: Immediate steps to investigate.
"""
    }

    @staticmethod
    def get_system_prompt(module_name: str) -> str:
        return PromptManager.SYSTEM_PROMPTS.get(module_name, "You are a cybersecurity assistant.")

    @staticmethod
    def format_phishing_prompt(email_subject: str, email_body: str, hf_data: dict = None) -> str:
        safe_body = PromptManager.sanitize_input(email_body)
        
        context = ""
        if hf_data and hf_data.get("status") == "success":
            context = f"\nAI Classification: {hf_data.get('label')} (Confidence: {hf_data.get('score'):.2f})"

        return f"""
        Subject: {email_subject}
        
        Body:
        {safe_body}
        
        {context}
        """

    @staticmethod
    def format_url_prompt(url: str, vt_data: dict = None, hf_data: dict = None) -> str:
        # Defang URL to prevent accidental clicking in logs/history
        defanged = url.replace("http", "hxxp").replace(".", "[.]")
        
        context = []
        if vt_data and vt_data.get("status") == "success":
            stats = vt_data.get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            context.append(f"VirusTotal Analysis: {malicious}/{total} vendors flagged as malicious")
        
        if hf_data and hf_data.get("status") == "success":
            context.append(f"AI Model Prediction: {hf_data.get('label')} (Score: {hf_data.get('score'):.2f})")
            
        context_str = "\n".join(context)

        return f"""
        Analyze the structure of this URL: {defanged}
        
        External Intelligence:
        {context_str}
        """

    @staticmethod
    def format_cve_prompt(cve_id: str, nvd_data: dict = None) -> str:
        description = "No description provided."
        metrics = ""
        
        if nvd_data and nvd_data.get("status") == "success":
            description = nvd_data.get("description", description)
            metrics = f"CVSS Score: {nvd_data.get('score')} ({nvd_data.get('severity')})"
            
        return f"""
        Explain vulnerability {cve_id}.
        
        Official Description:
        {description}
        
        {metrics}
        """

    @staticmethod
    def format_log_prompt(log_entry: str) -> str:
        safe_log = PromptManager.sanitize_input(log_entry)
        return f"Analyze this log entry:\n{safe_log}"

    @staticmethod
    def sanitize_input(text: str) -> str:
        """
        Basic sanitization to remove potential prompt injection attempts or excessive length.
        """
        # Trim whitespace
        text = text.strip()
        
        # Limit length to prevent context flooding (approx 2000 chars)
        if len(text) > 4000:
            text = text[:4000] + "...(truncated)"
            
        return text
