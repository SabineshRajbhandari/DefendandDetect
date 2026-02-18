import streamlit as st
from services.groq_service import groq_service
from prompts import PromptManager

def show_cve_module():
    st.header("🛡️ CVE Explainer")
    st.markdown("Find and understand the impact of specific vulnerabilities.")

    with st.expander("ℹ️ How it works"):
        st.markdown("""
        Search for a CVE (e.g., CVE-2021-44228) to get:
        - **Severity** (CVSS Score)
        - **Plain-English Impact**
        - **Mitigation Strategies**
        - **Real-world Examples**
        """)

    from services.database_service import DatabaseService

    # 1. Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "CVE":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        display_cve_results(res['input'], res['result'], is_history=True, id=res['id'])
        
        if st.button("Back to New Search"):
             st.session_state.restored_result = None
             st.rerun()
        return

    # 2. Check for active (unsaved) recent result
    if st.session_state.get("active_cve_result"):
        res = st.session_state.active_cve_result
        display_cve_results(res['cve_id'], res['result'])
        if st.button("Start New Search"):
            st.session_state.active_cve_result = None
            st.rerun()
        return

    cve_id = st.text_input("Enter CVE ID", placeholder="CVE-2021-44228")

    if st.button("Explain Vulnerability"):
        if not cve_id:
            st.warning("Please enter a CVE ID.")
            return

        with st.spinner("Fetching vulnerability data..."):
            user_prompt = PromptManager.format_cve_prompt(cve_id)
            system_prompt = PromptManager.get_system_prompt("cve")
            
            result = groq_service.execute_prompt(user_prompt, system_prompt)
            
            if result["status"] == "success":
                st.success("Analysis Complete")
                
                # Save to History
                DatabaseService.save_scan("CVE", cve_id, result)

                # Save to active session
                st.session_state.active_cve_result = {
                    "cve_id": cve_id,
                    "result": result
                }
                st.rerun()
            else:
                st.error(f"Analysis Failed: {result['error']}")

def display_cve_results(cve_id, result_data, is_history=False, id=None):
    st.subheader(f"Vulnerability Analysis: {cve_id}")
    
    if result_data.get("status") == "success":
        if result_data.get("thought"):
            with st.expander("🧠 AI Thinking Process"):
                st.write(result_data["thought"])
        
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
                report_content = ReportService.generate_markdown_report("CVE", cve_id, result_data)
                ext, mime = "md", "text/markdown"
            elif "JSON" in export_format:
                report_content = ReportService.generate_json_report("CVE", cve_id, result_data)
                ext, mime = "json", "application/json"
            elif "CSV" in export_format:
                report_content = ReportService.generate_csv_report("CVE", cve_id, result_data)
                ext, mime = "csv", "text/csv"
            elif "HTML" in export_format:
                report_content = ReportService.generate_html_report("CVE", cve_id, result_data)
                ext, mime = "html", "text/html"
            else:
                report_content = ReportService.generate_text_report("CVE", cve_id, result_data)
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
            fname = f"cve_{ts}.{ext}"
            st.download_button(
                f"🚀 Download as {ext.upper()}", 
                report_content, 
                file_name=fname, 
                mime=mime,
                key=f"dl_{id}" if id else "dl_active",
                use_container_width=True
            )