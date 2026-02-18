import streamlit as st
from services.groq_service import groq_service
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
        
        if st.button("Back to New Scan"):
             st.session_state.restored_result = None
             st.rerun()
        return

    # 2. Check for active (unsaved) recent result
    if st.session_state.get("active_phish_result"):
        res = st.session_state.active_phish_result
        display_phish_results(res['subject'], res['body'], res['result'])
        if st.button("Start New Analysis"):
            st.session_state.active_phish_result = None
            st.rerun()
        return

    subject = st.text_input("Email Subject (Optional)", placeholder="e.g., Urgent: Account Verification Required")
    body = st.text_area("Email Body", height=200, placeholder="Paste the email content here...")

    if st.button("Analyze Email"):
        if not body:
            st.warning("Please provide the email body.")
            return

        with st.spinner("Analyzing threat patterns..."):
            user_prompt = PromptManager.format_phishing_prompt(subject, body)
            system_prompt = PromptManager.get_system_prompt("phishing")
            
            result = groq_service.execute_prompt(user_prompt, system_prompt)
            
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
        st.markdown(f"**Subject:** {subject}")
    
    if result_data.get("status") == "success":
        groq_result = result_data
        
        if groq_result.get("thought"):
            with st.expander("🧠 AI Thinking Process"):
                st.write(groq_result["thought"])
        
        st.markdown("### 🛡️ Threat Report")
        st.markdown(groq_result["content"])

        st.markdown("---")
        with st.popover("📥 Export Report"):
            st.markdown("### 📤 Options")
            export_format = st.pills(
                "Select Format", 
                ["Markdown (.md)", "JSON (.json)", "Text (.txt)", "CSV (.csv)", "HTML (.html)"], 
                selection_mode="single",
                default="Markdown (.md)",
                key=f"fmt_{id}" if id else "fmt_active"
            )
            
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

            st.markdown("### 📝 Preview")
            with st.container(height=500, border=True):
                if ext == "md":
                    st.markdown(report_content)
                elif ext == "html":
                    st.components.v1.html(report_content, height=600, scrolling=True)
                else:
                    st.markdown(f"```text\n{report_content}\n```")

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