import streamlit as st
from services.groq_service import groq_service
from prompts import PromptManager

def show_cve_module():
    st.header("🛡️ CVE Vulnerability Explainer")
    st.markdown("Translate complex CVE descriptions into plain English for better understanding.")

    with st.expander("ℹ️ How it works"):
        st.markdown("""
        Takes a CVE ID (e.g., CVE-2021-44228) and provides:
        - Real-world impact analysis
        - Severity context
        - Mitigation strategies
        """)

    from services.database_service import DatabaseService

    # Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "CVE":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        
        st.text_input("CVE ID", value=res['input'], disabled=True)
        
        result_data = res['result']
        nvd_result = result_data.get("nvd_result", {})
        groq_result = result_data.get("groq_result", {})

        if nvd_result.get("status") == "success":
            st.info(f"**Official Data Found**: {nvd_result['id']} (Severity: {nvd_result['severity']} - {nvd_result['score']})")
            with st.expander("Show Official Description"):
                st.write(nvd_result['description'])
        
        if groq_result.get("status") == "success":
            if groq_result.get("thought"):
                with st.expander("🧠 AI Thinking Process"):
                    st.write(groq_result["thought"])
            
            st.markdown("### 📖 Vulnerability Insight")
            st.markdown(groq_result["content"])

            st.markdown("---")
            st.subheader("📥 Export Historical Report")
            export_format = st.radio("Select Format", ["Markdown (.md)", "JSON (.json)", "Text (.txt)"], horizontal=True, key="cve_hist_fmt")
            
            from services.report_service import ReportService
            if "Markdown" in export_format:
                report_content = ReportService.generate_markdown_report("CVE", res['input'], result_data)
                ext = "md"
            elif "JSON" in export_format:
                report_content = ReportService.generate_json_report("CVE", res['input'], result_data)
                ext = "json"
            else:
                report_content = ReportService.generate_text_report("CVE", res['input'], result_data)
                ext = "txt"

            st.download_button("📥 Finalize & Download Historical", report_content, file_name=f"cve_hist_{res['id']}.{ext}")

        if st.button("Start New Explanation"):
             st.session_state.restored_result = None
             st.rerun()
        return

    cve_id = st.text_input("CVE ID", placeholder="CVE-2021-44228")

    if st.button("Explain Vulnerability"):
        if not cve_id:
            st.warning("Please enter a CVE ID.")
            return

        with st.spinner("Analyzing security data..."):
            # 1. Fetch NVD Data
            from services.nvd_service import nvd_service
            nvd_result = nvd_service.fetch_cve(cve_id)
            
            if nvd_result.get("status") == "success":
                st.info(f"**Official Data Found**: {nvd_result['id']} (Severity: {nvd_result['severity']} - {nvd_result['score']})")
                with st.expander("Show Official Description"):
                    st.write(nvd_result['description'])
            elif nvd_result.get("status") == "not_found":
                st.warning("CVE ID not found in NVD database. Proceeding with general knowledge...")
            
            # 2. GROQ Explain
            user_prompt = PromptManager.format_cve_prompt(cve_id, nvd_result)
            system_prompt = PromptManager.get_system_prompt("cve")
            
            result = groq_service.execute_prompt(user_prompt, system_prompt)
            
            if result["status"] == "success":
                # Save to History
                full_result = {
                    "nvd_result": nvd_result,
                    "groq_result": result
                }
                DatabaseService.save_scan("CVE", cve_id, full_result)

                st.success("Explanation Generated")
                st.markdown("### 📖 Vulnerability Insight")
                st.markdown(result["content"])

                # Report Download Options
                st.markdown("---")
                st.subheader("📥 Export Final Analysis")
                export_format = st.radio("Select Format", ["Markdown (.md)", "JSON (.json)", "Text (.txt)"], horizontal=True, key="cve_fmt")
                
                from services.report_service import ReportService
                if "Markdown" in export_format:
                    report_content = ReportService.generate_markdown_report("CVE", cve_id, full_result)
                    ext = "md"
                elif "JSON" in export_format:
                    report_content = ReportService.generate_json_report("CVE", cve_id, full_result)
                    ext = "json"
                else:
                    report_content = ReportService.generate_text_report("CVE", cve_id, full_result)
                    ext = "txt"

                st.download_button("📥 Finalize & Download", report_content, file_name=f"cve_report.{ext}")
            else:
                st.error(f"Explanation Failed: {result['error']}")
