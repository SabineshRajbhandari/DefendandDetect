import streamlit as st
from services.groq_service import groq_service
from prompts import PromptManager

def show_log_module():
    st.header("📝 Security Log Translator")
    st.markdown("Translate raw, cryptic server logs into clear security insights.")

    with st.expander("ℹ️ How it works"):
        st.markdown("""
        Paste a raw log line (e.g., SSH auth failure, Apache error code) to get:
        - Event Summary
        - Threat Type
        - Actionable Next Steps
        """)

    from services.database_service import DatabaseService

    # Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "LOG":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        
        st.text_area("Log Entry", value=res['input'], height=150, disabled=True)
        
        result_data = res['result']
        if result_data.get("status") == "success":
             if result_data.get("thought"):
                 with st.expander("🧠 AI Thinking Process"):
                     st.write(result_data["thought"])
             
             st.markdown("### 📊 Log Analysis")
             st.markdown(result_data["content"])
             
             st.markdown("---")
             st.subheader("📥 Export Historical Report")
             export_format = st.radio("Select Format", ["Markdown (.md)", "JSON (.json)", "Text (.txt)"], horizontal=True, key="log_hist_fmt")
             
             from services.report_service import ReportService
             if "Markdown" in export_format:
                 report_content = ReportService.generate_markdown_report("LOG", res['input'], result_data)
                 ext = "md"
             elif "JSON" in export_format:
                 report_content = ReportService.generate_json_report("LOG", res['input'], result_data)
                 ext = "json"
             else:
                 report_content = ReportService.generate_text_report("LOG", res['input'], result_data)
                 ext = "txt"

             st.download_button("📥 Finalize & Download Historical", report_content, file_name=f"log_report_{res['id']}.{ext}")
        
        if st.button("Start New Translation"):
             st.session_state.restored_result = None
             st.rerun()
        return

    log_entry = st.text_area("Paste Log Entry", height=150, placeholder="Example: Feb 7 10:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 5000 ssh2")

    if st.button("Translate Log"):
        if not log_entry:
            st.warning("Please enter a log entry.")
            return

        with st.spinner("Analyzing security data..."):
            user_prompt = PromptManager.format_log_prompt(log_entry)
            system_prompt = PromptManager.get_system_prompt("logs")
            
            result = groq_service.execute_prompt(user_prompt, system_prompt)
            
            if result["status"] == "success":
                # Save to History
                DatabaseService.save_scan("LOG", log_entry[:100], result)

                st.success("Translation Complete")
                st.markdown("### 📊 Log Analysis")
                st.markdown(result["content"])

                # Report Download Options
                st.markdown("---")
                st.subheader("📥 Export Final Analysis")
                export_format = st.radio("Select Format", ["Markdown (.md)", "JSON (.json)", "Text (.txt)"], horizontal=True, key="log_fmt")
                
                from services.report_service import ReportService
                if "Markdown" in export_format:
                    report_content = ReportService.generate_markdown_report("LOG", log_entry, result)
                    ext = "md"
                elif "JSON" in export_format:
                    report_content = ReportService.generate_json_report("LOG", log_entry, result)
                    ext = "json"
                else:
                    report_content = ReportService.generate_text_report("LOG", log_entry, result)
                    ext = "txt"

                st.download_button("📥 Finalize & Download", report_content, file_name=f"log_report.{ext}")
            else:
                st.error(f"Translation Failed: {result['error']}")
