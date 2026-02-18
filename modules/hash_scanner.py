import streamlit as st
import hashlib
from services.virustotal_service import VirusTotalService
from services.groq_service import groq_service
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

    # Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "HASH":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        
        st.text_input("File Hash", value=res['input'], disabled=True)
        
        result_data = res['result']
        vt_result = result_data.get('vt_result', {})
        groq_result = result_data.get('groq_result', {})
        
        display_results(vt_result, groq_result, res['input'])
        
        if st.button("Start New Scan"):
             st.session_state.restored_result = None
             st.rerun()
        return

    uploaded_file = st.file_uploader("Upload a file to scan", type=None)

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        
        st.info(f"**SHA-256**: `{file_hash}`")
        
        if st.button("Query VirusTotal"):
            with st.spinner("Analyzing security data..."):
                # 1. VirusTotal Lookup
                vt_result = VirusTotalService.check_file_hash(file_hash)
                
                # 2. AI Reasoning (Optional but good for education)
                system_prompt = "You are a Malware Analysis Instructor. Explain the significance of the following file scan result."
                user_prompt = f"The file with SHA-256 hash {file_hash} has these VirusTotal results: {vt_result}. Explain what this means in plain English."
                
                groq_result = groq_service.execute_prompt(user_prompt, system_prompt)
                
                # Save to History
                full_result = {
                    "vt_result": vt_result,
                    "groq_result": groq_result
                }
                DatabaseService.save_scan("HASH", file_hash, full_result)
                
                display_results(vt_result, groq_result, file_hash)

def display_results(vt_result, groq_result, file_hash):
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

            # Report Download Options
            st.markdown("---")
            st.subheader("📥 Export Final Analysis")
            export_format = st.radio("Select Format", ["Markdown (.md)", "JSON (.json)", "Text (.txt)"], horizontal=True, key="hash_fmt")
            
            from services.report_service import ReportService
            report_data = {"vt_result": vt_result, "groq_result": groq_result}
            
            if "Markdown" in export_format:
                report_content = ReportService.generate_markdown_report("HASH", file_hash, report_data)
                ext = "md"
            elif "JSON" in export_format:
                report_content = ReportService.generate_json_report("HASH", file_hash, report_data)
                ext = "json"
            else:
                report_content = ReportService.generate_text_report("HASH", file_hash, report_data)
                ext = "txt"

            st.download_button("📥 Finalize & Download", report_content, file_name=f"file_hash_report.{ext}")
        else:
            st.warning("AI Analysis Unavailable")
