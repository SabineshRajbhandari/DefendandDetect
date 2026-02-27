import streamlit as st
import hashlib
from services.virustotal_service import VirusTotalService
from services.groq_service import groq_service
from services.report_service import ReportService
from prompts import PromptManager

def show_hash_scanner():
    st.header("🔍 File Hash Scanner")
    st.markdown("Scan file fingerprints (SHA-256) to check for known malware without uploading the actual file.")

    with st.expander("ℹ️ How it works"):
        st.markdown("""
        1.  **Local Hashing**: We calculate the SHA-256 "fingerprint" of your file in the browser (or your local server).
        2.  **Reputation Lookup**: We check this fingerprint against VirusTotal's database of millions of known samples.
        3.  **No Upload**: Your actual file content never leaves this application.
        """)

    from services.database_service import DatabaseService

    # 1. Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "HASH":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        display_results(res['result'].get('vt_result', {}), res['result'].get('groq_result', {}), res['input'], is_history=True, id=res['id'])
        
        return

    # 2. Check for active (unsaved) recent result
    if st.session_state.get("active_hash_result"):
        res = st.session_state.active_hash_result
        display_results(res['vt_result'], res['groq_result'], res['file_hash'])
        return

    uploaded_file = st.file_uploader("Upload a file to scan", type=None)

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        
        st.info(f"**SHA-256**: `{file_hash}`")
        
        if st.button("Query VirusTotal"):
            # Set active state to empty initially to show spinner clearly
            with st.spinner("Analyzing security data..."):
                # 1. VirusTotal Lookup
                vt_result = VirusTotalService.check_file_hash(file_hash)
                
                # 2. AI Reasoning
                system_prompt = PromptManager.get_system_prompt("hash")
                user_prompt = f"Explain the security significance of SHA-256 fingerprint: {file_hash} with these results: {vt_result}"
                
                groq_result = groq_service.execute_prompt(user_prompt, system_prompt)
                
                full_result = {
                    "vt_result": vt_result,
                    "groq_result": groq_result
                }
                
                # Save to History
                DatabaseService.save_scan("HASH", file_hash, full_result)

                # Save to active session
                st.session_state.active_hash_result = {
                    "file_hash": file_hash,
                    "vt_result": vt_result,
                    "groq_result": groq_result
                }
                st.rerun()

def display_results(vt_result, groq_result, file_hash, is_history=False, id=None):
    st.info(f"**SHA-256**: `{file_hash}`")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("VirusTotal Reputation")
        if vt_result.get("status") == "success":
            if vt_result.get("is_malicious"):
                st.error(f"🚨 MALICIOUS ({vt_result['stats']['malicious']} vendors)")
            elif "message" in vt_result:
                st.success(f"✅ {vt_result['message']}")
            else:
                st.success("✅ Clean")
            
            if "stats" in vt_result:
                st.json(vt_result["stats"])
        else:
            st.error(f"Query Failed: {vt_result.get('message')}")

    with col2:
        st.subheader("AI Analysis")
        if groq_result.get("status") == "success":
            if groq_result.get("thought"):
                with st.expander("🧠 AI Thinking Process"):
                    st.write(groq_result["thought"])
            st.markdown(groq_result["content"])

    st.markdown("---")
    
    c1, c2 = st.columns(2)
    with c1:
        if st.button("🔄 Start New Scan", use_container_width=True, key=f"new_{id}" if id else "new_active"):
            st.session_state.active_hash_result = None
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
            report_data = {"vt_result": vt_result, "groq_result": groq_result}
            
            if "Markdown" in export_format:
                report_content = ReportService.generate_markdown_report("HASH", file_hash, report_data)
                ext, mime = "md", "text/markdown"
            elif "JSON" in export_format:
                report_content = ReportService.generate_json_report("HASH", file_hash, report_data)
                ext, mime = "json", "application/json"
            elif "CSV" in export_format:
                report_content = ReportService.generate_csv_report("HASH", file_hash, report_data)
                ext, mime = "csv", "text/csv"
            elif "HTML" in export_format:
                report_content = ReportService.generate_html_report("HASH", file_hash, report_data)
                ext, mime = "html", "text/html"
            else:
                report_content = ReportService.generate_text_report("HASH", file_hash, report_data)
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
            fname = f"hash_{ts}.{ext}"
            st.download_button(
                f"🚀 Download as {ext.upper()}", 
                report_content, 
                file_name=fname, 
                mime=mime,
                key=f"dl_{id}" if id else "dl_active",
                use_container_width=True
            )
