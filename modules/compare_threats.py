import streamlit as st
import pandas as pd
import difflib
import json
import html
import re
from services.database_service import DatabaseService
from services.intelligence_service import IntelligenceService
from services.virustotal_service import VirusTotalService
from datetime import datetime

def text_diff(text1, text2):
    """Generates a color-coded HTML diff with length protection and CSS classes."""
    try:
        # Limit diff size to prevent browser/memory crashes on huge logs/emails
        if len(text1) > 5000: text1 = text1[:5000] + "...(truncated)"
        if len(text2) > 5000: text2 = text2[:5000] + "...(truncated)"
        
        result = ""
        codes = difflib.SequenceMatcher(None, text1, text2).get_opcodes()
        for tag, i1, i2, j1, j2 in codes:
            if tag == 'equal':
                result += html.escape(text1[i1:i2])
            elif tag == 'delete':
                result += f'<span class="diff-del">{html.escape(text1[i1:i2])}</span>'
            elif tag == 'insert':
                result += f'<span class="diff-ins">{html.escape(text2[j1:j2])}</span>'
            elif tag == 'replace':
                result += f'<span class="diff-del">{html.escape(text1[i1:i2])}</span>'
                result += f'<span class="diff-ins">{html.escape(text2[j1:j2])}</span>'
        return result
    except Exception:
        return "Error generating visual diff."

def show_compare_mode():
    try:
        _show_compare_mode_internal()
    except Exception as e:
        st.error(f"☢️ **Critical Workbench Failure**: {str(e)}")
        st.info("The forensic engine encountered an unexpected data structure. Please try refreshing or selecting different scans.")

def _show_compare_mode_internal():
    st.header("⚖️ Advanced Compare Mode")
    st.markdown("Perform forensic differential analysis across all security sectors.")

    # --- Mode Selector (Button Style) ---
    if "compare_src" not in st.session_state:
        st.session_state.compare_src = "History"

    col_btn1, col_btn2, col_btn_sp = st.columns([1, 1, 3])
    with col_btn1:
        if st.button("📂 Browse History", type="primary" if st.session_state.compare_src == "History" else "secondary", use_container_width=True):
            st.session_state.compare_src = "History"
            st.rerun()
    with col_btn2:
        if st.button("⚡ Live Mode", type="primary" if st.session_state.compare_src == "Live" else "secondary", use_container_width=True):
            st.session_state.compare_src = "Live"
            st.rerun()

    scan_a, scan_b = None, None

    if st.session_state.compare_src == "History":
        all_history = DatabaseService.get_all_history()
        
        if not all_history or len(all_history) < 2:
            st.info("🔎 **Insufficient Data**: You need at least two scans in your history to perform a comparison.")
            return

        c1, c2 = st.columns(2)

        def render_history_selector(col, scan_key, label):
            with col:
                st.subheader(label)
                
                # --- Independent Filters ---
                f_col1, f_col2 = st.columns([2, 1])
                with f_col1:
                    filter_sector = st.selectbox(f"Filter Sector", ["ALL", "URL", "PHISHING", "HASH", "CVE", "LOG"], key=f"f_sec_{scan_key}")
                with f_col2:
                    sort_order = st.selectbox(f"Sort", ["Newest", "Oldest"], key=f"sort_{scan_key}")

                # Apply Filtering
                filtered = all_history
                if filter_sector != "ALL":
                    filtered = [item for item in filtered if item.get('type') == filter_sector]
                
                # Apply Sorting
                if sort_order == "Oldest":
                    filtered = filtered[::-1]

                if not filtered:
                    st.warning(f"No {filter_sector} scans found.")
                    return None

                # Selection with Placeholder
                options = ["🔍 Select Scan..."] + [
                    f"[{item.get('type', 'UNK')}] {item.get('input', '')[:35]}... ({item.get('timestamp', 'N/A')})" 
                    for item in filtered
                ]
                
                selected_label = st.selectbox("Select Scan", options=options, key=f"sel_{scan_key}", index=0)
                
                if selected_label == "🔍 Select Scan...":
                    return None
                
                # Reverse the label back to scan - matching by input/timestamp since labels are complex
                # This is safer than finding index since placeholders shift indices.
                match = next((item for item in filtered if f"[{item.get('type', 'UNK')}] {item.get('input', '')[:35]}... ({item.get('timestamp', 'N/A')})" == selected_label), None)
                return match

        scan_a_tmp = render_history_selector(c1, "a", "Scan A")
        scan_b_tmp = render_history_selector(c2, "b", "Scan B")

        if scan_a_tmp and scan_b_tmp:
            if st.button("🚀 Compare Selected History Scans", use_container_width=True, type="primary"):
                st.session_state.hist_compare_a = scan_a_tmp
                st.session_state.hist_compare_b = scan_b_tmp
        
        if "hist_compare_a" in st.session_state and "hist_compare_b" in st.session_state:
            # Check if selections still valid (user might have changed selectivity after clicking)
            if scan_a_tmp and scan_b_tmp:
                 scan_a, scan_b = st.session_state.hist_compare_a, st.session_state.hist_compare_b
            else:
                # Reset if user changed one of the dropdowns to placeholder
                st.session_state.pop("hist_compare_a", None)
                st.session_state.pop("hist_compare_b", None)
    
    else:
        st.subheader("⚡ Live Multi-Sector Comparison")
        comp_type = st.pills("Select Forensic Sector", ["URL", "PHISHING", "HASH", "CVE", "LOG"], default="URL")
        
        # Sector-specific configuration
        sector_config = {
            "URL": {"placeholder": "e.g., https://secure-login.com", "regex": r"^(https?:\/\/)([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$"},
            "PHISHING": {"placeholder": "Paste suspicious email body or text...", "min_len": 10},
            "HASH": {"placeholder": "Paste SHA-256 file fingerprint...", "regex": r"^[a-fA-F0-9]{64}$"},
            "CVE": {"placeholder": "e.g., CVE-2021-44228", "regex": r"^CVE-\d{4}-\d{4,}$"},
            "LOG": {"placeholder": "Paste raw security log line...", "min_len": 10}
        }
        
        config = sector_config[comp_type]
        
        col_in_a, col_in_b = st.columns(2)
        with col_in_a:
            input_a = st.text_area(f"Live {comp_type} A", placeholder=config["placeholder"], height=150).strip()
        with col_in_b:
            input_b = st.text_area(f"Live {comp_type} B", placeholder=config["placeholder"], height=150).strip()

        if st.button("🚀 Analyze & Compare Live Inputs", use_container_width=True, type="primary"):
            def validate(val, cfg):
                if not val: return False, "Input cannot be empty."
                if "regex" in cfg and not re.match(cfg["regex"], val, re.IGNORECASE): return False, f"Invalid {comp_type} format."
                if "min_len" in cfg and len(val) < cfg["min_len"]: return False, f"Input too short."
                return True, ""

            is_valid_a, err_a = validate(input_a, config)
            is_valid_b, err_b = validate(input_b, config)

            if not is_valid_a or not is_valid_b:
                if not is_valid_a: st.error(f"A: {err_a}")
                if not is_valid_b: st.error(f"B: {err_b}")
            else:
                if comp_type in ["HASH", "CVE"]: input_a, input_b = input_a.upper(), input_b.upper()
                with st.spinner("🛰️ Gathering Intelligence..."):
                    def fetch_live_scan(content, t_type):
                        res = {"status": "success"}
                        try:
                            if t_type == "URL":
                                res["whois"] = IntelligenceService.get_whois_data(content)
                                res["geo"] = IntelligenceService.get_geo_info(content)
                                res["lexical"] = {"entropy": IntelligenceService.calculate_entropy(content), "lookalike": IntelligenceService.check_lookalike(content.split('/')[2] if '//' in content else content)}
                            elif t_type == "PHISHING":
                                res["yara"] = IntelligenceService.scan_yara(content)
                                res["lexical"] = {"entropy": IntelligenceService.calculate_entropy(content)}
                            elif t_type == "HASH":
                                res["vt_result"] = VirusTotalService.check_file_hash(content)
                                res["lexical"] = {"entropy": IntelligenceService.calculate_entropy(content)}
                            else:
                                res["lexical"] = {"entropy": IntelligenceService.calculate_entropy(content)}
                        except Exception as e:
                            res["status"] = "error"
                            res["message"] = str(e)
                        return {"id": "LIVE", "type": t_type, "input": content, "timestamp": datetime.now().strftime("%Y-%m-%d %I:%M %p"), "result": res}
                    
                    st.session_state.live_scan_a = fetch_live_scan(input_a, comp_type)
                    st.session_state.live_scan_b = fetch_live_scan(input_b, comp_type)

        if "live_scan_a" in st.session_state and "live_scan_b" in st.session_state:
            scan_a, scan_b = st.session_state.live_scan_a, st.session_state.live_scan_b

    if not scan_a or not scan_b:
        return

    # --- 1. Visual Delta Dashboard ---
    res_a, res_b = scan_a.get('result', {}), scan_b.get('result', {})
    whois_a, whois_b = res_a.get('whois') or {}, res_b.get('whois') or {}
    geo_a, geo_b = res_a.get('geo') or {}, res_b.get('geo') or {}
    vt_a, vt_b = res_a.get('vt_result') or {}, res_b.get('vt_result') or {}
    lex_a, lex_b = res_a.get('lexical') or {}, res_b.get('lexical') or {}

    st.markdown("#### 📊 Intelligence Delta Dashboard")
    try:
        def get_stat_with_indicator(val_a, val_b, label_suffix=""):
            indicator = "🟢" if val_a == val_b and val_a not in ["N/A", "UNK", 0] else "⚪"
            if val_a != val_b: indicator = "🔴"
            return f"{indicator} {val_a} {label_suffix}".strip()

        ent_a, ent_b = lex_a.get('entropy', 0), lex_b.get('entropy', 0)
        ent_delta = f"({ent_b - ent_a:+.2f})" if isinstance(ent_a, (int, float)) and isinstance(ent_b, (int, float)) else ""

        len_a, len_b = len(scan_a.get('input', '')), len(scan_b.get('input', ''))
        len_delta = f"({len_b - len_a:+.0f})"

        delta_metrics = {
            "Forensic Metric": ["Security Sector", "Registrar / Source", "Origin / Reputation", "Randomness (Entropy)", "Data Volume"],
            "Scan A": [
                scan_a.get('type', 'UNK'),
                whois_a.get('registrar', 'N/A') if scan_a.get('type') == "URL" else f"ID: #{scan_a.get('id', '0')}",
                geo_a.get('country', 'N/A') if scan_a.get('type') == "URL" else (f"{vt_a.get('stats', {}).get('malicious', 0)} Flags" if scan_a.get('type') == "HASH" else "N/A"),
                f"{ent_a}",
                f"{len_a} ch"
            ],
            "Scan B": [
                get_stat_with_indicator(scan_a.get('type'), scan_b.get('type')),
                get_stat_with_indicator(whois_a.get('registrar'), whois_b.get('registrar')) if scan_a.get('type') == scan_b.get('type') == "URL" else get_stat_with_indicator(scan_a.get('id'), scan_b.get('id')),
                get_stat_with_indicator(geo_a.get('country'), geo_b.get('country')) if scan_a.get('type') == scan_b.get('type') == "URL" else get_stat_with_indicator(vt_a.get('stats', {}).get('malicious', -1), vt_b.get('stats', {}).get('malicious', -1), "Flags"),
                f"{get_stat_with_indicator(ent_a, ent_b)} {ent_delta}",
                f"{get_stat_with_indicator(len_a, len_b)} {len_delta}"
            ]
        }
        st.table(pd.DataFrame(delta_metrics))
    except Exception as table_err:
        st.error(f"Error rendering Dashboard: {table_err}")

    # --- 2. Structural Highlighting (Visual Diff) ---
    with st.expander("🔍 Structural Input Diff", expanded=True):
        st.markdown('<div class="diff-container">' + text_diff(scan_a.get('input', ''), scan_b.get('input', '')) + '</div>', unsafe_allow_html=True)
        st.caption("Red = Unique to A | Green = Unique to B | White = Common in Both")

    if st.session_state.compare_src == "History":
        col_a, col_b = st.columns(2)
        def render_scan(col, scan, title):
            with col:
                st.markdown(f"#### {title}")
                if scan and "result" in scan:
                    if "content" in scan['result']:
                        with st.container(height=300, border=True): st.markdown(scan['result']["content"])
        render_scan(col_a, scan_a, "Scan A")
        render_scan(col_b, scan_b, "Scan B")
