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
    if st.session_state.get("active_phish_result"):
        res = st.session_state.active_phish_result
        display_phish_results(res['subject'], res['body'], res['result'])
        return

    subject = st.text_input("Email Subject (Optional)", placeholder="e.g., Urgent: Account Verification Required")
    body = st.text_area("Email Body", height=200, placeholder="Paste the email content here...")

    if st.button("Analyze Email"):
        if not body or len(body.strip()) < 20:
            st.warning("⚠️ **Input Too Short**: Please provide at least 20 characters of email content for a meaningful analysis.")
            return

        # 🔍 Visual Skeleton Loading State
        placeholder = st.empty()
        with placeholder.container():
            st.markdown('<div class="scanning-bar"></div>', unsafe_allow_allow_html=True)
            st.markdown('<div class="skeleton-box" style="height: 100px;"></div>', unsafe_allow_html=True)
            st.markdown('<div class="skeleton-box" style="height: 300px;"></div>', unsafe_allow_html=True)
            st.info("🧠 **AI Reasoning in Progress...** Deconstructing email headers and social engineering tactics.")

        from services.intelligence_service import IntelligenceService
        
        user_prompt = PromptManager.format_phishing_prompt(subject, body)
        system_prompt = PromptManager.get_system_prompt("phishing")
        
        result = groq_service.execute_prompt(user_prompt, system_prompt)
        
        # Run YARA Intelligence Scan
        combined_text = f"Subject: {subject}\nBody: {body}"
        yara_data = IntelligenceService.scan_yara(combined_text)
        result["yara"] = yara_data
        
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

def display_phish_results(subject, body, result_data, is_history=False, id=None):
    if subject and subject != "[Historical Scan]":
        st.info(f"**Subject:** {subject}")
    
    st.text_area("Email Content", value=body, height=200, disabled=True, key=f"body_{id}" if id else "current_body")
    
    if result_data.get("status") == "success":
        # Render YARA Intelligence if available
        if "yara" in result_data and result_data["yara"]["status"] == "success":
            y = result_data["yara"]
            with st.expander("📝 Signature Analysis (YARA)", expanded=True):
                if y["match_count"] > 0:
                    st.error(f"⚠️ **{y['match_count']} Malicious Signatures Detected**")
                    for rule in y["matches"]:
                        st.markdown(f"- **Detected Pattern**: `{rule.replace('_', ' ').title()}`")
                    st.warning("These patterns are common indicators of malicious intent found in verified phishing campaigns.")
                else:
                    st.success("✅ No known phishing signatures detected in structural scan.")

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
