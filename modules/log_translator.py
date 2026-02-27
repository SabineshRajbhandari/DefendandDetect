import streamlit as st
from services.groq_service import groq_service
from services.report_service import ReportService
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

    # 1. Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "LOG":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        display_log_results(res['input'], res['result'], is_history=True, id=res['id'])
        
        return

    # 2. Check for active (unsaved) recent result
    if st.session_state.get("active_log_result"):
        res = st.session_state.active_log_result
        display_log_results(res['log_entry'], res['result'])
        return

    log_entry = st.text_area("Paste Log Entry", height=150, placeholder="Example: Feb 7 10:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 5000 ssh2")

    if st.button("Translate Log"):
        if not log_entry or len(log_entry.strip()) < 10:
            st.warning("⚠️ **Input Too Short**: Please provide at least 10 characters of log data for a valid translation.")
            return

        with st.spinner("Analyzing security data..."):
            user_prompt = PromptManager.format_log_prompt(log_entry)
            system_prompt = PromptManager.get_system_prompt("logs")
            
            result = groq_service.execute_prompt(user_prompt, system_prompt)
            
            if result["status"] == "success":
                st.success("Translation Complete")
                
                # Save to History
                DatabaseService.save_scan("LOG", log_entry[:100], result)

                # Save to active session
                st.session_state.active_log_result = {
                    "log_entry": log_entry,
                    "result": result
                }
                st.rerun()
            else:
                st.error(f"Translation Failed: {result['error']}")

def display_log_results(log_entry, result_data, is_history=False, id=None):
    st.text_area("Log Entry", value=log_entry, height=150, disabled=True, key=f"log_{id}" if id else "current_log")
    
    if result_data.get("status") == "success":
        if result_data.get("thought"):
            with st.expander("🧠 AI Thinking Process"):
                st.write(result_data["thought"])
        
        st.markdown("### 📊 Log Analysis")
        st.markdown(result_data["content"])

        st.markdown("---")
        
        c1, c2 = st.columns(2)
        with c1:
            if st.button("🔄 Start New Scan", use_container_width=True, key=f"new_{id}" if id else "new_active"):
                st.session_state.active_log_result = None
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
                
                from datetime import datetime
                
                if "Markdown" in export_format:
                    report_content = ReportService.generate_markdown_report("LOG", log_entry, result_data)
                    ext, mime = "md", "text/markdown"
                elif "JSON" in export_format:
                    report_content = ReportService.generate_json_report("LOG", log_entry, result_data)
                    ext, mime = "json", "application/json"
                elif "CSV" in export_format:
                    report_content = ReportService.generate_csv_report("LOG", log_entry, result_data)
                    ext, mime = "csv", "text/csv"
                elif "HTML" in export_format:
                    report_content = ReportService.generate_html_report("LOG", log_entry, result_data)
                    ext, mime = "html", "text/html"
                else:
                    report_content = ReportService.generate_text_report("LOG", log_entry, result_data)
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
                fname = f"log_{ts}.{ext}"
                st.download_button(
                    f"🚀 Download as {ext.upper()}", 
                    report_content, 
                    file_name=fname, 
                    mime=mime,
                    key=f"dl_{id}" if id else "dl_active",
                    use_container_width=True
                )
