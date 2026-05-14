
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
You are a Cybersecurity Instructor and SOC Analyst.
Your goal is to translate the raw, cryptic server log entry into plain English that a beginner IT student or small business owner can easily understand.
FIRST, provide your internal reasoning process inside a <thought> block.
THEN, provide the following sections using highly detailed, well-spaced formatting (do NOT use emojis):
1. **Event Summary**: A simple, highly descriptive, jargon-free explanation of exactly what happened.
2. **Threat Level & Type**: (e.g., High Risk - Brute Force Attack, Low Risk - Routine Error). Explain *why* you gave this rating.
3. **Reading the Log**: Carefully break down the gibberish in the log into clear bullet points. Explain what the specific IP addresses, port numbers, or error codes actually mean in plain English.
4. **Forensic Context**: If the system provided IP geolocation context, summarize what it means for the risk level and the attacker's origin.
5. **Action Required**: Clear, highly detailed, step-by-step instructions on what to do next to secure the system.
Keep the tone exceptionally helpful, highly detailed, educational, and very easy to read. Structure your output beautifully with bolding and spacing.
""",
        "hash": """
You are a Malware Analysis Instructor.
Explain the significance of the following file scan results (SHA-256 fingerprint).
FIRST, provide your internal reasoning process inside a <thought> block.
THEN, provide the following sections:
1. **Reputation Summary**: (Clean / Suspicious / Malicious) based on vendor flags.
2. **Technical Interpretation**: What does this file fingerprint tell us?
3. **Safety Advice**: Should the user execute this file?
4. **Learning Moment**: A brief technical detail about hashing or malware signatures.
""",
        "breach": """
You are a Privacy and Identity Protection Specialist.
Analyze the provided data breach intelligence (either an email breach history or password exposure count).
FIRST, provide your internal reasoning process inside a <thought> block.
THEN, provide the following sections:
1. **Exposure Summary**: What was exposed and how bad is it?
2. **Risk Assessment**: What can attackers do with this specific type of exposed data? (e.g., Credential Stuffing, Phishing, SIM Swapping).
3. **Immediate Action Plan**: Step-by-step instructions on what the user MUST do right now (e.g., Change password, enable 2FA).
4. **Privacy Lesson**: A brief, beginner-friendly lesson on why data breaches happen and how k-Anonymity or password hashing works.
Keep the tone exceptionally helpful, highly detailed, educational, and very easy to read. Structure your output beautifully with bolding and spacing.
"""
    }

    @staticmethod
    def get_system_prompt(module_name: str) -> str:
        return PromptManager.SYSTEM_PROMPTS.get(module_name, "You are a cybersecurity assistant.")

    @staticmethod
    def format_phishing_prompt(email_subject: str, email_body: str, hf_data: dict = None, whois_data: dict = None) -> str:
        safe_body = PromptManager.sanitize_input(email_body)
        
        context = []
        if hf_data and hf_data.get("status") == "success":
            context.append(f"HuggingFace ML Classification: {hf_data.get('label')} (Confidence: {hf_data.get('score'):.2f})")
            
        if whois_data:
            context.append(f"Extracted Links Domain Intelligence: {whois_data}")

        context_str = "\n".join(context)
        if context_str:
            context_str = f"\n[SYSTEM AUTOMATION] Extracted Technical Intelligence:\n{context_str}"

        return f"""
        Subject: {email_subject}
        
        Body:
        {safe_body}
        {context_str}
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
    def format_cve_prompt(cve_id: str, nvd_data: dict = None, epss_data: dict = None, cisa_data: dict = None) -> str:
        description = "No description provided."
        metrics = []
        
        if nvd_data and nvd_data.get("status") == "success":
            description = nvd_data.get("description", description)
            metrics.append(f"CVSS Score: {nvd_data.get('score')} ({nvd_data.get('severity')})")
            metrics.append(f"Vector: {nvd_data.get('vector')}")
            if nvd_data.get("cwes"):
                metrics.append(f"CWE Mapping: {', '.join(nvd_data.get('cwes'))}")
            
        if epss_data and epss_data.get("status") == "success":
            metrics.append(f"EPSS Score: {epss_data.get('epss')} (Probability of exploitation in next 30 days)")

        if cisa_data and cisa_data.get("is_exploited"):
            metrics.append("CRITICAL: This vulnerability is on the CISA KEV list (confirmed active exploitation).")
            
        metrics_str = "\n".join(metrics)
            
        return f"""
        Explain vulnerability {cve_id}.
        
        Official Description:
        {description}

        Intelligence Metrics:
        {metrics_str}
        """

    @staticmethod
    def format_log_prompt(log_entry: str) -> str:
        safe_log = PromptManager.sanitize_input(log_entry)
        return f"Analyze this log entry:\n{safe_log}"

    @staticmethod
    def format_breach_prompt(target_type: str, target: str, breach_data: dict) -> str:
        safe_target = PromptManager.sanitize_input(target)
        # Avoid putting the raw password in the prompt if it's a password check
        if target_type == "Password":
            safe_target = "[REDACTED PASSWORD]"
            
        return f"""
        Analyze this {target_type} Breach Result:
        Target: {safe_target}
        
        API Response / Intelligence Data:
        {breach_data}
        """


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
