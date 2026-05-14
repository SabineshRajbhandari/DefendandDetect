import streamlit as st
from services.groq_service import groq_service
from services.report_service import ReportService
from prompts import PromptManager

import re

def show_url_analyzer():
    st.header("URL Analyzer")
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
        
        return

    # 2. Check for active (unsaved) recent result
    # We will display this below the input form instead of hiding the form

    url = st.text_input("Suspicious URL", placeholder="https://login-security-update.com/verify").strip()

    if st.button("Analyze Link"):
        if not url:
            st.warning("Please enter a URL.")
            return

        # Regex Validation for URL (Require http:// or https:// for safety)
        url_pattern = r"^(https?:\/\/)([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$"
        if not re.match(url_pattern, url.lower()):
            st.error("❌ **Invalid Format**: Please enter a valid URL including protocol (e.g., https://example.com).")
            return

        # 🔍 Visual Skeleton Loading State
        placeholder = st.empty()
        with placeholder.container():
            st.markdown('<div class="skeleton-box" style="height: 100px;"></div>', unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            with c1: st.markdown('<div class="skeleton-box" style="height: 200px;"></div>', unsafe_allow_html=True)
            with c2: st.markdown('<div class="skeleton-box" style="height: 200px;"></div>', unsafe_allow_html=True)
            st.markdown('<div class="skeleton-box" style="height: 150px;"></div>', unsafe_allow_html=True)
            st.info("🧠 **AI Reasoning in Progress...** Analyzing domain reputation and structural patterns.")

        from services.virustotal_service import VirusTotalService
        from services.intelligence_service import IntelligenceService
        
        # Deep Intelligence Lookups
        vt_result = VirusTotalService.check_url(url)
        domain = url.split('://')[-1].split('/')[0]
        
        user_prompt = PromptManager.format_url_prompt(url, vt_result)
        system_prompt = PromptManager.get_system_prompt("url")
        
        result = groq_service.execute_prompt(user_prompt, system_prompt)
        
        result["vt_result"] = vt_result
        result["whois"] = IntelligenceService.get_whois_data(url)
        result["geo"] = IntelligenceService.get_geo_info(url)
        result["redirects"] = IntelligenceService.get_redirect_chain(url)
        result["lexical"] = {
            "entropy": IntelligenceService.calculate_entropy(domain),
            "lookalike": IntelligenceService.check_lookalike(domain),
            "yara": IntelligenceService.scan_yara(url)
        }
        
        # Clear skeleton
        placeholder.empty()

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

    st.markdown("---")
    if st.session_state.get("active_url_result"):
        res = st.session_state.active_url_result
        display_url_results(res['url'], res['result'])

def display_url_results(url, result_data, is_history=False, id=None):
    st.info(f"**URL:** `{url}`")
    
    if result_data.get("status") == "success":
        # 🚨 VirusTotal Gauge
        vt = result_data.get("vt_result", {})
        if vt.get("status") == "success":
            stats = vt.get("stats", {})
            if stats:
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                color = "#ef4444" if malicious > 0 else "#10b981"
                
                st.markdown(f"""
                    <div style="background: {color}22; padding: 15px; border-radius: 10px; border-left: 5px solid {color}; margin-bottom: 20px;">
                        <span style="font-size: 0.9rem; color: var(--text-secondary);">VirusTotal Reputation Score</span><br/>
                        <span style="font-size: 1.8rem; font-weight: bold; color: {color};">{malicious} / {total} Vendors Flagged</span>
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.success(f"✅ {vt.get('message', 'URL not found in VT database (likely clean or unscanned).')}")
        # 🟢 Layer 1: DNS & WHOIS
        if "whois" in result_data and result_data["whois"]["status"] == "success":
            w = result_data["whois"]
            with st.expander("🛰️ Domain Intelligence (WHOIS)", expanded=False):
                c1, c2, c3 = st.columns(3)
                with c1: st.metric("Domain Age", f"{w['age_days']} Days" if w['age_days'] is not None else "Unknown")
                with c2: st.metric("Registrar", w['registrar'] if w['registrar'] else "Unknown")
                with c3: st.metric("Status", "NEW / HIGH RISK" if w['is_new'] else "ESTABLISHED", delta="⚠️" if w['is_new'] else None)
                if w['is_new']: st.warning("🚨 **High Risk Warning**: This domain was registered recently.")
                st.caption(f"Created: {w['creation_date']} | Expires: {w['expiration_date']}")

        # 🟡 Layer 2: Infrastructure (IP & Geo)
        if "geo" in result_data and result_data["geo"]["status"] == "success":
            g = result_data["geo"]
            with st.expander("📍 Infrastructure & Geolocation", expanded=False):
                c1, c2, c3 = st.columns(3)
                with c1: st.metric("IP Address", g["ip"])
                with c2: st.metric("Country", g["country"])
                with c3: st.metric("ISP", g["isp"][:20])
                st.caption(f"AS: {g['as']} | Org: {g['org']}")

        # 🟠 Layer 3: Behavioral (Redirect Chain)
        if "redirects" in result_data and result_data["redirects"]["status"] == "success":
            r = result_data["redirects"]
            with st.expander(f"🔄 Redirect Behavioral Chain ({r['depth']} Jumps)", expanded=r["is_redirected"]):
                if r["is_redirected"]:
                    for i, step in enumerate(r["chain"]):
                        st.markdown(f"{i}. `{step}`")
                    st.warning("⚠️ **Redirect Detected**: The final destination differs from the original link. This is a common tactic to hide malicious landing pages.")
                else:
                    st.success("✅ **Direct Link**: No redirects detected.")

        # 🔴 Side-by-Side: Lexical Analysis & AI Thinking
        col_lex, col_ai = st.columns(2)
        
        with col_lex:
            if "lexical" in result_data:
                lex = result_data["lexical"]
                with st.container(height=350, border=True):
                    st.markdown("### 🧠 Lexical Risk Analysis")
                    st.caption("Analyzing the 'makeup' of the domain name.")
                    
                    c1, c2 = st.columns(2)
                    with c1:
                        st.metric("Randomness", f"{lex['entropy']}", help="Higher numbers (>4.0) often mean the name was generated by a computer (DGA), which is a common hacker tactic.")
                        if lex["entropy"] > 4.2: st.error("🚨 **High Randomness**: This name looks like gibberish.")
                    with c2:
                        if lex["lookalike"]["status"] == "warning":
                            st.metric("Deception Risk", "HIGH", delta="⚠️", help="This domain looks very similar to a famous brand.")
                            st.warning(f"🚨 Mimicking: **{lex['lookalike']['match']}**")
                        else:
                            st.metric("Deception Risk", "CLEAR")
                            st.success("No famous brand lookalikes.")
                    
                    if lex.get("yara") and lex["yara"].get("status") == "success":
                        st.divider()
                        y = lex["yara"]
                        if y["match_count"] > 0:
                            st.error(f"⚠️ {y['match_count']} YARA URL Matches")
                            for m in y["matches"]: st.code(m)
                        else:
                            st.success("YARA: No URL patterns found")

        with col_ai:
            if result_data.get("thought"):
                with st.container(height=350, border=True):
                    st.markdown("### 🔍 AI Thinking Process")
                    st.caption("Behind-the-scenes logic used by the AI.")
                    st.write(result_data["thought"])

        st.markdown("### 📊 Structural Analysis")
        st.markdown(result_data["content"])

        st.markdown("---")
        
        c1, c2 = st.columns(2)
        with c1:
            if st.button("🔄 Start New Scan", use_container_width=True, key=f"new_{id}" if id else "new_active"):
                st.session_state.active_url_result = None
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
                fname = f"url_{ts}.{ext}"
                st.download_button(
                    f"🚀 Download as {ext.upper()}", 
                    report_content, 
                    file_name=fname, 
                    mime=mime,
                    key=f"dl_{id}" if id else "dl_active",
                    use_container_width=True
                )
