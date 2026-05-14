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
        display_results(res['result'].get('vt_result', {}), res['result'].get('groq_result', {}), res['input'], res['result'].get('static_analysis', {}), is_history=True, id=res['id'])
        
        return

    # 2. Check for active (unsaved) recent result
    # Displayed below form

    col_up, col_man = st.columns(2)
    with col_up:
        uploaded_file = st.file_uploader("Upload a file to scan (Static Analysis + VirusTotal)", type=None)
    with col_man:
        manual_hash = st.text_input("Enter a SHA-256 Hash manually (VirusTotal Only)", placeholder="e.g. 44d88612fea8a8f36de82e1278abb02f...")

    file_bytes = None
    file_hash = None
    is_pdf = False

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        is_pdf = uploaded_file.name.lower().endswith('.pdf')
    elif manual_hash:
        file_hash = manual_hash.strip().lower()

    if file_hash:
        st.info(f"**Target SHA-256**: `{file_hash}`")
        
        if st.button("Analyze Threat"):
            with st.spinner("Analyzing security data..."):
                # 1. Static Analysis (if file uploaded)
                static_analysis = {}
                if file_bytes:
                    from services.intelligence_service import IntelligenceService
                    static_analysis["entropy"] = IntelligenceService.calculate_file_entropy(file_bytes)
                    
                    try:
                        text_for_yara = file_bytes.decode('utf-8', errors='ignore')
                        static_analysis["yara"] = IntelligenceService.scan_yara(text_for_yara)
                    except Exception:
                        pass
                        
                    # Advanced Forensic Analysis
                    static_analysis["file_type"] = IntelligenceService.check_file_type(file_bytes)
                    static_analysis["strings"] = IntelligenceService.get_binary_strings(file_bytes)
                    
                    if is_pdf:
                        static_analysis["pdf"] = IntelligenceService.analyze_pdf(file_bytes)

                # 2. VirusTotal Lookup
                vt_result = VirusTotalService.check_file_hash(file_hash)
                
                # 3. AI Reasoning
                system_prompt = PromptManager.get_system_prompt("hash")
                user_prompt = f"Explain the security significance of SHA-256 fingerprint: {file_hash}\n"
                user_prompt += f"VirusTotal Results: {vt_result}\n"
                if static_analysis:
                    user_prompt += f"Local Static Analysis Findings: {static_analysis}\n"
                
                groq_result = groq_service.execute_prompt(user_prompt, system_prompt)
                
                full_result = {
                    "vt_result": vt_result,
                    "groq_result": groq_result,
                    "static_analysis": static_analysis
                }
                
                # Save to History
                DatabaseService.save_scan("HASH", file_hash, full_result)

                # Save to active session
                st.session_state.active_hash_result = {
                    "file_hash": file_hash,
                    "vt_result": vt_result,
                    "groq_result": groq_result,
                    "static_analysis": static_analysis
                }
                st.rerun()

    st.markdown("---")
    if st.session_state.get("active_hash_result"):
        res = st.session_state.active_hash_result
        display_results(res['vt_result'], res['groq_result'], res['file_hash'], res.get('static_analysis', {}))

def display_results(vt_result, groq_result, file_hash, static_analysis=None, is_history=False, id=None):
    if static_analysis is None:
        static_analysis = {}
    
    if is_history:
        st.info(f"**Target SHA-256**: `{file_hash}`")
    
    # Render Static Analysis if available
    if static_analysis:
        with st.expander("🔬 Local Static Analysis Findings", expanded=True):
            cols = st.columns(3)
            if "entropy" in static_analysis:
                ent = static_analysis["entropy"]
                with cols[0]:
                    st.metric("Shannon Entropy", f"{ent} / 8.0")
                    if ent > 7.0:
                        st.error("High Entropy: Possible packed/encrypted file.")
            
            if "pdf" in static_analysis and static_analysis["pdf"].get("status") == "success":
                pdf = static_analysis["pdf"]
                with cols[1]:
                    st.metric("PDF Pages", pdf["pages"])
                    if pdf["is_suspicious"]:
                        st.error("🚨 Suspicious PDF Objects Found!")
                        for flag in pdf["flags"]:
                            st.markdown(f"- {flag}")
                    else:
                        st.success("No standard malicious PDF triggers found.")
            
            if "yara" in static_analysis and static_analysis["yara"].get("status") == "success":
                yara_res = static_analysis["yara"]
                with cols[2]:
                    if yara_res["match_count"] > 0:
                        st.error(f"⚠️ {yara_res['match_count']} YARA Matches")
                    else:
                        st.success("YARA: Clean")

            st.markdown("---")
            f1, f2 = st.columns(2)
            with f1:
                st.write(f"**Detected File Type:** `{static_analysis.get('file_type', 'Unknown')}`")
            with f2:
                if static_analysis.get("strings"):
                    with st.expander("🔗 Extracted Forensic Strings (URLs/APIs)"):
                        for s in static_analysis["strings"]:
                            st.code(s, language=None)

    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("VirusTotal Reputation")
        if vt_result.get("status") == "success":
            # 📊 Visual Severity Gauge
            stats = vt_result.get('stats', {})
            if stats:
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                color = "#ef4444" if malicious > 0 else "#10b981"
                
                st.markdown(f"""
                    <div style="background: {color}22; padding: 15px; border-radius: 10px; border-left: 5px solid {color}; margin-bottom: 20px;">
                        <span style="font-size: 0.9rem; color: var(--text-secondary);">Threat Detection Rate</span><br/>
                        <span style="font-size: 1.8rem; font-weight: bold; color: {color};">{malicious} / {total} Vendors</span>
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.success(f"✅ {vt_result.get('message', 'Hash not found in VT database (likely clean or unknown).')}")

            if vt_result.get("threat_label") and vt_result.get("threat_label") != "N/A":
                st.warning(f"**Suggested Label:** {vt_result['threat_label']}")
            
            if vt_result.get("tags"):
                st.write("**Analysis Tags:**")
                st.caption(", ".join(vt_result["tags"]))
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
            report_data = {"vt_result": vt_result, "groq_result": groq_result, "static_analysis": static_analysis}
            
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
