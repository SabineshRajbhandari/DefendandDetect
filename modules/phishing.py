import streamlit as st
from services.groq_service import groq_service
from services.report_service import ReportService
from prompts import PromptManager

def show_phishing_module():
    st.header("📧 Phishing Detector")
    st.markdown("Analyze emails to identify social engineering red flags.")

    with st.expander("ℹ️ How it works"):
        st.markdown("""
        Paste the content of a suspicious email (subject and body) to get:
        - **Threat Level** (Safe, Suspicious, Malicious)
        - **Red Flag Analysis**
        - **Safety Recommendations**
        """)

    from services.database_service import DatabaseService
    
    # 1. Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "PHISHING":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        display_phish_results("[Historical Scan]", res['input'], res['result'], is_history=True, id=res['id'])
        
        return

    # 2. Check for active (unsaved) recent result
    # Displayed below form

    t1, t2 = st.tabs(["✍️ Simple Paste", "🔬 Deep Header Analysis"])
    
    with t1:
        subject = st.text_input("Email Subject (Optional)", placeholder="e.g., Urgent: Account Verification Required")
        body = st.text_area("Email Body", height=200, placeholder="Paste the email content here...")
    
    with t2:
        headers = st.text_area("Raw Email Headers (Optional)", height=250, placeholder="Paste headers from Gmail/Outlook here...")
        st.caption("Analyzing headers can reveal SPF/DKIM failures and the true sender IP.")

    if st.button("Analyze Email"):
        if not body or len(body.strip()) < 20:
            st.warning("⚠️ **Input Too Short**: Please provide at least 20 characters of email content for a meaningful analysis.")
            return

        # 🔍 Visual Skeleton Loading State
        placeholder = st.empty()
        with placeholder.container():
            st.markdown('<div class="skeleton-box" style="height: 100px;"></div>', unsafe_allow_html=True)
            st.markdown('<div class="skeleton-box" style="height: 300px;"></div>', unsafe_allow_html=True)
            st.info("🧠 **AI Reasoning in Progress...** Deconstructing email headers and social engineering tactics.")

        from services.intelligence_service import IntelligenceService
        from services.huggingface_service import HuggingFaceService
        import re
        
        # 1. URL Extraction & Defanging
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        extracted_urls = list(set(re.findall(url_pattern, body)))
        
        whois_intel = {}
        defanged_urls = []
        for u in extracted_urls:
            defanged = u.replace("http", "hxxp").replace(".", "[.]")
            defanged_urls.append(defanged)
            
            # 2. Domain WHOIS Check
            w_data = IntelligenceService.get_whois_data(u)
            if w_data.get("status") == "success":
                whois_intel[defanged] = w_data
                
        # 3. HuggingFace ML Classification
        hf_result = HuggingFaceService.classify_phishing(body)
        
        # 4. Llama 3 AI Analysis
        user_prompt = PromptManager.format_phishing_prompt(subject, body, hf_result, whois_intel)
        system_prompt = PromptManager.get_system_prompt("phishing")
        
        result = groq_service.execute_prompt(user_prompt, system_prompt)
        
        # Run YARA Intelligence Scan
        combined_text = f"Subject: {subject}\nBody: {body}"
        yara_data = IntelligenceService.scan_yara(combined_text)
        result["yara"] = yara_data
        result["hf_result"] = hf_result
        result["whois_intel"] = whois_intel
        result["defanged_urls"] = defanged_urls
        
        # 5. Header Intelligence (if provided)
        if headers:
            from services.intelligence_service import IntelligenceService
            # Simple header extraction for educational purpose
            sender_ip = re.search(r"Received: from .*?\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", headers)
            if sender_ip:
                result["sender_geo"] = IntelligenceService.get_geo_info(sender_ip.group(1))
            
            spf = re.search(r"spf=(pass|fail|softfail|neutral)", headers, re.I)
            dkim = re.search(r"dkim=(pass|fail)", headers, re.I)
            result["auth_status"] = {"spf": spf.group(1) if spf else "Unknown", "dkim": dkim.group(1) if dkim else "Unknown"}
        
        # Clear skeleton
        placeholder.empty()

        if result["status"] == "success":
            st.success("Analysis Complete")
            
            # Save to History
            DatabaseService.save_scan("PHISHING", f"Sub: {subject[:30]}...", result)

            # Save to active session
            st.session_state.active_phish_result = {
                "subject": subject,
                "body": body,
                "result": result
            }
            st.rerun()
        else:
            st.error(f"Analysis Failed: {result['error']}")

    st.markdown("---")
    if st.session_state.get("active_phish_result"):
        res = st.session_state.active_phish_result
        display_phish_results(res['subject'], res['body'], res['result'])

def display_phish_results(subject, body, result_data, is_history=False, id=None):
    if subject and subject != "[Historical Scan]":
        st.info(f"**Subject:** {subject}")
    
    st.text_area("Email Content", value=body, height=200, disabled=True, key=f"body_{id}" if id else "current_body")
    
    if result_data.get("status") == "success":
        # 📊 Visual Severity Gauge
        if "hf_result" in result_data and result_data["hf_result"].get("status") == "success":
            hf = result_data["hf_result"]
            score = hf['score']
            is_phish = hf['label'].lower() == 'phishing'
            color = "#ef4444" if is_phish and score > 0.7 else "#f59e0b" if is_phish else "#10b981"
            
            st.markdown(f"""
                <div style="background: {color}22; padding: 15px; border-radius: 10px; border-left: 5px solid {color}; margin-bottom: 20px;">
                    <span style="font-size: 0.9rem; color: var(--text-secondary);">Phishing ML Verdict</span><br/>
                    <span style="font-size: 1.8rem; font-weight: bold; color: {color};">{hf['label']} ({score:.1%})</span>
                </div>
            """, unsafe_allow_html=True)
            
        # 📨 Header Intelligence Display
        if "auth_status" in result_data:
            with st.expander("🔬 Email Authentication Forensic (Headers)", expanded=True):
                c1, c2, c3 = st.columns(3)
                auth = result_data["auth_status"]
                with c1: st.metric("SPF Status", auth["spf"], delta="FAIL" if auth["spf"] == "fail" else None)
                with c2: st.metric("DKIM Status", auth["dkim"], delta="FAIL" if auth["dkim"] == "fail" else None)
                
                if "sender_geo" in result_data and result_data["sender_geo"].get("status") == "success":
                    geo = result_data["sender_geo"]
                    with c3: st.metric("Source IP Location", f"{geo['country']}")
                    st.caption(f"Origin IP: {geo['ip']} | ISP: {geo['isp']}")
            
        # Render YARA Intelligence if available
        if "yara" in result_data and result_data["yara"].get("status") == "success":
            y = result_data["yara"]
            with st.expander("📝 Signature Analysis (YARA)", expanded=True):
                if y["match_count"] > 0:
                    st.error(f"⚠️ **{y['match_count']} Malicious Signatures Detected**")
                    for rule in y["matches"]:
                        st.markdown(f"- **Detected Pattern**: `{rule.replace('_', ' ').title()}`")
                    st.warning("These patterns are common indicators of malicious intent found in verified phishing campaigns.")
                else:
                    st.success("✅ No known phishing signatures detected in structural scan.")
                    
        # Render URL Intelligence
        if "defanged_urls" in result_data and result_data["defanged_urls"]:
            with st.expander("🔗 Extracted Links (Defanged & Safe)", expanded=True):
                for d_url in result_data["defanged_urls"]:
                    st.code(d_url)
                    whois_info = result_data.get("whois_intel", {}).get(d_url)
                    if whois_info:
                        age = whois_info.get("age_days")
                        if age is not None:
                            if age < 30:
                                st.error(f"🚨 **CRITICAL RISK**: Domain is newly registered ({age} days old)!")
                            else:
                                st.info(f"Domain Age: {age} days")
                        else:
                            st.warning("Domain Age: Unknown")

        groq_result = result_data
        
        if groq_result.get("thought"):
            with st.expander("🧠 AI Thinking Process"):
                st.write(groq_result["thought"])
        
        st.markdown("### 🛡️ Threat Report")
        st.markdown(groq_result["content"])

        st.markdown("---")
        
        c1, c2 = st.columns(2)
        with c1:
            if st.button("🔄 Start New Scan", use_container_width=True, key=f"new_{id}" if id else "new_active"):
                st.session_state.active_phish_result = None
                st.session_state.restored_result = None
                st.rerun()
                
        with c2:
            with st.popover("📤 Export Report", use_container_width=True):
                col_opt1, col_opt2 = st.columns([2, 1])
                with col_opt1:
                    export_format = st.pills(
                        "Select Format", 
                        ["Markdown (.md)", "JSON (.json)", "Text (.txt)", "CSV (.csv)", "HTML (.html)"], 
                        selection_mode="single",
                        default="Markdown (.md)",
                        key=f"fmt_{id}" if id else "fmt_active"
                    )
                with col_opt2:
                    wrap_text = st.checkbox("Word Wrap", value=True, key=f"wrap_{id}" if id else "wrap_active")
                
                from services.report_service import ReportService
                from datetime import datetime
                
                # Match extension and mime
                if "Markdown" in export_format:
                    report_content = ReportService.generate_markdown_report("PHISHING", body, result_data)
                    ext, mime = "md", "text/markdown"
                elif "JSON" in export_format:
                    report_content = ReportService.generate_json_report("PHISHING", body, result_data)
                    ext, mime = "json", "application/json"
                elif "CSV" in export_format:
                    report_content = ReportService.generate_csv_report("PHISHING", body, result_data)
                    ext, mime = "csv", "text/csv"
                elif "HTML" in export_format:
                    report_content = ReportService.generate_html_report("PHISHING", body, result_data)
                    ext, mime = "html", "text/html"
                else:
                    report_content = ReportService.generate_text_report("PHISHING", body, result_data)
                    ext, mime = "txt", "text/plain"
    
                with st.container(height=500, border=True):
                    if wrap_text:
                        if ext == "md":
                            st.markdown(report_content)
                        elif ext == "html":
                            st.components.v1.html(report_content, height=600, scrolling=True)
                        else:
                            st.text(report_content)
                    else:
                        st.code(report_content, language=ext if ext != 'txt' else None)
    
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                fname = f"phish_{ts}.{ext}"
                st.download_button(
                    f"🚀 Download as {ext.upper()}", 
                    report_content, 
                    file_name=fname, 
                    mime=mime,
                    key=f"dl_{id}" if id else "dl_active",
                    use_container_width=True
                )
