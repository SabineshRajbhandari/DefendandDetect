import streamlit as st
from services.groq_service import groq_service
from prompts import PromptManager

def show_url_analyzer():
    st.header("🔗 URL Analyzer")
    st.markdown("Deconstruct suspicious links to understand their intent.")

    with st.expander("ℹ️ How it works"):
        st.markdown("""
        Enter a suspicious URL to get:
        - Domain Reputation Info
        - Path & Parameter Analysis
        - Potential Redirect Chains
        - Threat Score & Classification
        """)

    from services.database_service import DatabaseService

    # 1. Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "URL":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        display_url_results(res['input'], res['result'], is_history=True, id=res['id'])
        
        if st.button("Back to New Scan"):
             st.session_state.restored_result = None
             st.rerun()
        return

    # 2. Check for active (unsaved) recent result
    if st.session_state.get("active_url_result"):
        res = st.session_state.active_url_result
        display_url_results(res['url'], res['result'])
        if st.button("Start New Analysis"):
            st.session_state.active_url_result = None
            st.rerun()
        return

    url = st.text_input("Suspicious URL", placeholder="https://login-security-update.com/verify")

    if st.button("Analyze Link"):
        if not url:
            st.warning("Please enter a URL.")
            return

        with st.spinner("Analyzing URL structure..."):
            user_prompt = PromptManager.format_url_prompt(url)
            system_prompt = PromptManager.get_system_prompt("urls")
            
            result = groq_service.execute_prompt(user_prompt, system_prompt)
            
            if result["status"] == "success":
                st.success("Analysis Complete")
                
                # Save to History
                DatabaseService.save_scan("URL", url, result)

                # Save to active session
                st.session_state.active_url_result = {
                    "url": url,
                    "result": result
                }
                st.rerun()
            else:
                st.error(f"Analysis Failed: {result['error']}")

def display_url_results(url, result_data, is_history=False, id=None):
    st.info(f"**URL:** `{url}`")
    
    if result_data.get("status") == "success":
        if result_data.get("thought"):
            with st.expander("🧠 AI Thinking Process"):
                st.write(result_data["thought"])
        
        st.markdown("### 📊 Structural Analysis")
        st.markdown(result_data["content"])

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
            
            if "Markdown" in export_format:
                report_content = ReportService.generate_markdown_report("URL", url, result_data)
                ext, mime = "md", "text/markdown"
            elif "JSON" in export_format:
                report_content = ReportService.generate_json_report("URL", url, result_data)
                ext, mime = "json", "application/json"
            elif "CSV" in export_format:
                report_content = ReportService.generate_csv_report("URL", url, result_data)
                ext, mime = "csv", "text/csv"
            elif "HTML" in export_format:
                report_content = ReportService.generate_html_report("URL", url, result_data)
                ext, mime = "html", "text/html"
            else:
                report_content = ReportService.generate_text_report("URL", url, result_data)
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
            fname = f"url_{ts}.{ext}"
            st.download_button(
                f"🚀 Download as {ext.upper()}", 
                report_content, 
                file_name=fname, 
                mime=mime,
                key=f"dl_{id}" if id else "dl_active",
                use_container_width=True
            )