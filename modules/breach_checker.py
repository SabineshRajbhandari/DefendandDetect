import streamlit as st
from services.groq_service import groq_service
from services.report_service import ReportService
from prompts import PromptManager
from services.database_service import DatabaseService
from services.intelligence_service import IntelligenceService
from datetime import datetime

def show_breach_module():
    st.header("🗄️ Breach Exposure Checker")
    st.markdown("Check if your email or passwords have been exposed in known data breaches.")

    with st.expander("ℹ️ How it works & Privacy Guarantee"):
        st.markdown("""
        **Emails**: We simulate checking your email against known breach databases (e.g., LinkedIn, Adobe) to see if your data is circulating on the dark web.
        
        **Passwords**: We use the official **HaveIBeenPwned** API with a technique called **k-Anonymity**. 
        1. We hash your password locally on your device.
        2. We only send the *first 5 characters* of the hash to the API. 
        3. The API doesn't know your password, but tells us if it matches millions of known hacked passwords.
        """)

    # 1. Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "BREACH":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        # For history, we just show the output.
        display_breach_results(res['input'], res['result'], is_history=True, id=res['id'])
        return

    tab_email, tab_pass = st.tabs(["📧 Email Breach Scan", "🔑 Password Safety Scan"])

    with tab_email:
        st.markdown("### Search Data Breaches")
        st.markdown("Find out if your email address was exposed in known corporate data leaks.")
        target_email = st.text_input("Enter Email Address", placeholder="e.g. user@example.com")
        if st.button("Check Email Exposure"):
            if not target_email or "@" not in target_email:
                st.warning("Please enter a valid email address.")
                return
            
            with st.spinner("Checking breach databases..."):
                intel_data = IntelligenceService.simulate_email_breach(target_email)
                process_breach_check("Email", target_email, intel_data)

    with tab_pass:
        st.markdown("### Check Password Safety")
        st.markdown("Safely test if a password has been compromised. We use *k-Anonymity*, meaning your actual password is **never** sent over the internet.")
        target_pass = st.text_input("Enter Password", type="password", placeholder="Enter a password to test")
        if st.button("Check Password Safety"):
            if not target_pass or len(target_pass) < 3:
                st.warning("Please enter a longer password to test.")
                return
                
            with st.spinner("Hashing and checking k-Anonymity database..."):
                intel_data = IntelligenceService.check_pwned_password(target_pass)
                process_breach_check("Password", target_pass, intel_data)

    st.markdown("---")

    # 2. Check for active (unsaved) recent result
    if st.session_state.get("active_breach_result"):
        res = st.session_state.active_breach_result
        display_breach_results(res['target'], res['result'])

def process_breach_check(target_type, target, intel_data):
    user_prompt = PromptManager.format_breach_prompt(target_type, target, intel_data)
    system_prompt = PromptManager.get_system_prompt("breach")
    
    result = groq_service.execute_prompt(user_prompt, system_prompt)
    result["intel_data"] = intel_data
    result["target_type"] = target_type
    
    if result["status"] == "success":
        st.success("Analysis Complete")
        
        # Save to History
        # Only save email to history, NOT password
        save_target = target if target_type == "Email" else "[REDACTED PASSWORD]"
        DatabaseService.save_scan("BREACH", f"{target_type}: {save_target}", result)

        # Save to active session
        st.session_state.active_breach_result = {
            "target": save_target,
            "result": result
        }
        st.rerun()
    else:
        st.error(f"Analysis Failed: {result['error']}")

def display_breach_results(target, result_data, is_history=False, id=None):
    st.info(f"**Checked Target:** `{target}`")
    
    intel = result_data.get("intel_data", {})
    target_type = result_data.get("target_type", "Unknown")
    
    # Display Hard Intelligence
    if target_type == "Password" and intel.get("status") == "success":
        with st.expander("🛡️ k-Anonymity Password Intelligence", expanded=True):
            if intel.get("pwned"):
                st.error(f"🚨 **CRITICAL RISK:** This password has been seen **{intel['count']:,}** times in data breaches!")
                st.markdown(f"**Local Hash Prefix sent to API:** `{intel['hash_prefix']}`")
            else:
                st.success("✅ **SAFE:** This password was NOT found in any known database leaks.")
                
    elif target_type == "Email" and intel.get("status") == "success":
        with st.expander("🗄️ Known Data Breaches", expanded=True):
            if intel.get("breached"):
                st.error(f"🚨 **EXPOSED:** This email was found in {len(intel['breaches'])} known data breaches.")
                for b in intel["breaches"]:
                    st.markdown(f"- **{b['Name']}** ({b['BreachDate']}): Leaked {', '.join(b['DataClasses'])}")
            else:
                st.success("✅ **SAFE:** This email was not found in any known major data breaches.")

    # Display AI Analysis
    if result_data.get("status") == "success":
        if result_data.get("thought"):
            with st.expander("🧠 AI Thinking Process"):
                st.write(result_data["thought"])
                
        st.markdown("### 📋 Mitigation Plan")
        st.markdown(result_data["content"])

        st.markdown("---")
        
        c1, c2 = st.columns(2)
        with c1:
            if st.button("🔄 Start New Scan", use_container_width=True, key=f"new_{id}" if id else "new_active"):
                st.session_state.active_breach_result = None
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
                
                # Report generation logic
                if "Markdown" in export_format:
                    report_content = ReportService.generate_markdown_report("BREACH", target, result_data)
                    ext, mime = "md", "text/markdown"
                elif "JSON" in export_format:
                    report_content = ReportService.generate_json_report("BREACH", target, result_data)
                    ext, mime = "json", "application/json"
                elif "CSV" in export_format:
                    report_content = ReportService.generate_csv_report("BREACH", target, result_data)
                    ext, mime = "csv", "text/csv"
                elif "HTML" in export_format:
                    report_content = ReportService.generate_html_report("BREACH", target, result_data)
                    ext, mime = "html", "text/html"
                else:
                    report_content = ReportService.generate_text_report("BREACH", target, result_data)
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
                fname = f"breach_{ts}.{ext}"
                st.download_button(
                    f"🚀 Download as {ext.upper()}", 
                    report_content, 
                    file_name=fname, 
                    mime=mime,
                    key=f"dl_{id}" if id else "dl_active",
                    use_container_width=True
                )
