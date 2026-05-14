import streamlit as st
from services.groq_service import groq_service
from services.report_service import ReportService
from prompts import PromptManager

import re
import html

def parse_cvss_vector(vector):
    """Translates a CVSS vector string into human-readable definitions."""
    if not vector or vector == "N/A": return {}
    
    mapping = {
        "AV": ("Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
        "AC": ("Complexity", {"L": "Low", "H": "High"}),
        "PR": ("Privileges", {"N": "None", "L": "Low", "H": "High"}),
        "UI": ("User Interaction", {"N": "None", "R": "Required"}),
        "S":  ("Scope", {"U": "Unchanged", "C": "Changed"}),
        "C":  ("Confidentiality", {"N": "None", "L": "Low", "H": "High"}),
        "I":  ("Integrity", {"N": "None", "L": "Low", "H": "High"}),
        "A":  ("Availability", {"N": "None", "L": "Low", "H": "High"})
    }
    
    parts = vector.split("/")
    decoded = {}
    for part in parts:
        if ":" in part:
            k, v = part.split(":")
            if k in mapping:
                label, values = mapping[k]
                decoded[label] = values.get(v, v)
    return decoded

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
        
        return

    # 2. Check for active (unsaved) recent result
    # Displayed below form

    cve_id = st.text_input("Enter CVE ID", placeholder="CVE-2021-44228").strip().upper()

    if st.button("Explain Vulnerability"):
        if not cve_id:
            st.warning("Please enter a CVE ID.")
            return
        
        # Regex Validation for CVE: CVE-YYYY-NNNN(N)
        cve_pattern = r"^CVE-\d{4}-\d{4,}$"
        if not re.match(cve_pattern, cve_id):
            st.error("❌ **Invalid Format**: Please enter a valid CVE ID (e.g., CVE-2021-44228).")
            return

        with st.spinner("🛰️ Querying NIST NVD Database..."):
            from services.nvd_service import NVDService
            nvd_intel = NVDService.fetch_cve(cve_id)

        with st.spinner("🚨 Checking CISA & EPSS Intelligence..."):
            from services.threat_intel_service import threat_intel_service
            cisa_intel = threat_intel_service.check_cisa_kev(cve_id)
            epss_intel = threat_intel_service.fetch_epss_score(cve_id)
            
        with st.spinner("🧠 AI Reasoning in Progress..."):
            user_prompt = PromptManager.format_cve_prompt(cve_id, nvd_intel, epss_intel, cisa_intel)
            system_prompt = PromptManager.get_system_prompt("cve")
            
            result = groq_service.execute_prompt(user_prompt, system_prompt)
            result["nvd_intel"] = nvd_intel 
            result["cisa_intel"] = cisa_intel
            result["epss_intel"] = epss_intel
            
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

    st.markdown("---")
    if st.session_state.get("active_cve_result"):
        res = st.session_state.active_cve_result
        display_cve_results(res['cve_id'], res['result'])

def display_cve_results(cve_id, result_data, is_history=False, id=None):
    st.info(f"**CVE ID:** `{cve_id}`")
    
    if result_data.get("status") == "success":
        nvd = result_data.get("nvd_intel", {})
        cisa = result_data.get("cisa_intel", {})
        epss = result_data.get("epss_intel", {})

        # 🚨 CISA KEV Warning
        if cisa and cisa.get("is_exploited"):
            st.error(f"""
            ### 🚨 CRITICAL: Known Exploited Vulnerability
            This CVE is listed in the **CISA KEV Catalog**. 
            **Action Required:** {cisa['details'].get('requiredAction', 'Patch immediately.')}
            **Due Date:** {cisa['details'].get('dueDate', 'N/A')}
            """, icon="⚠️")

        # 📊 Severity & Prediction Dashboard
        if nvd and nvd.get("status") == "success":
            with st.container(border=True):
                c1, c2, c3 = st.columns([2, 1, 1])
                with c1:
                    score = float(nvd.get("score", 0))
                    color = "#ef4444" if score >= 7 else "#f59e0b" if score >= 4 else "#10b981"
                    st.markdown(f"""
                        <div style="background: {color}22; padding: 15px; border-radius: 10px; border-left: 5px solid {color};">
                            <span style="font-size: 0.9rem; color: var(--text-secondary);">CVSS v3.x Severity</span><br/>
                            <span style="font-size: 2rem; font-weight: bold; color: {color};">{score} / 10.0</span>
                        </div>
                    """, unsafe_allow_html=True)
                
                with c2:
                    st.metric("EPSS Prob.", f"{epss.get('epss', 0)*100:.2f}%", help="Probability of exploitation in next 30 days")
                with c3:
                    st.metric("Percentile", f"{epss.get('percentile', 0)*100:.1f}th")

            with st.expander("🔬 Forensic Breakdown (Vector & CWE)"):
                v_col, c_col = st.columns(2)
                with v_col:
                    st.caption("CVSS Vector Breakdown")
                    vector_map = parse_cvss_vector(nvd.get("vector", ""))
                    for label, val in vector_map.items():
                        st.write(f"**{label}:** {val}")
                with c_col:
                    st.caption("CWE Mappings")
                    for cwe in nvd.get("cwes", []):
                        st.code(cwe)
                
                st.markdown("**Original Description:**")
                st.caption(nvd.get('description'))

        if result_data.get("thought"):
            with st.expander("🧠 AI Thinking Process"):
                st.write(result_data["thought"])
        
        st.markdown("### 🔍 AI Forensic Analysis & Remediation")
        st.markdown(result_data["content"])

        # 🛠️ References & Patch Links
        if nvd.get("references"):
            with st.expander("🛠️ Official Patch Links & References"):
                st.table(nvd["references"][:10]) # Show top 10 refs

        st.markdown("---")
        
        c1, c2 = st.columns(2)
        with c1:
            if st.button("🔄 Start New Scan", use_container_width=True, key=f"new_{id}" if id else "new_active"):
                st.session_state.active_cve_result = None
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
                fname = f"cve_{ts}.{ext}"
                st.download_button(
                    f"🚀 Download as {ext.upper()}", 
                    report_content, 
                    file_name=fname, 
                    mime=mime,
                    key=f"dl_{id}" if id else "dl_active",
                    use_container_width=True
                )
