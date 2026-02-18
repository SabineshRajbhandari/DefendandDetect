import streamlit as st
from services.groq_service import groq_service
from prompts import PromptManager

def show_phishing_module():
    st.header("📧 AI Phishing Detector")
    st.markdown("Analyze suspicious emails to identify potential social engineering attacks.")

    with st.expander("ℹ️ How it works"):
        st.markdown("""
        This module uses AI to scan email content for:
        - Urgency and fear tactics
        - Suspicious sender patterns
        - Malicious links or attachments requests
        """)

    from services.database_service import DatabaseService

    # Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "PHISHING":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        
        # Display saved input
        st.text_input("Email Subject", value="[Historical Scan]", disabled=True)
        st.text_area("Email Body", value=res['input'], height=200, disabled=True)
        
        # Display saved result
        # Display saved result
        result_data = res['result']
        hf_result = result_data.get('hf_result', {})
        groq_result = result_data.get('groq_result', {})
        
        if hf_result.get("status") == "success":
             st.info(f"Probabilistic Model: **{hf_result['label']}** ({hf_result['score']:.1%})")
        
        if groq_result.get("status") == "success":
             if groq_result.get("thought"):
                 with st.expander("🧠 AI Thinking Process"):
                     st.write(groq_result["thought"])
             
             st.markdown("### 🛡️ Threat Report")
             st.markdown(groq_result["content"])
             
             # Report Download
             from services.report_service import ReportService
             report_md = ReportService.generate_markdown_report("PHISHING", res['input'], result_data)
             st.download_button("📥 Download Analysis Report", report_md, file_name=f"phishing_report_{res['id']}.md")
        
        if st.button("Start New Scan"):
             st.session_state.restored_result = None
             st.rerun()
        return

    email_subject = st.text_input("Email Subject", placeholder="e.g. URGENT: Account Suspension")
    email_body = st.text_area("Email Body", height=200, placeholder="Paste the email content here...")

    if st.button("Analyze Email"):
        if not email_body:
            st.warning("Please enter the email body.")
            return

        with st.spinner("Running hybrid analysis (Hugging Face + GROQ)..."):
            # 1. Hugging Face Classification
            from services.huggingface_service import hf_service
            hf_result = hf_service.classify_phishing(email_body[:512]) # Truncate for BERT models often limited to 512 tokens
            
            # Show fast result immediately if possible (or just use it for context)
            if hf_result.get("status") == "success":
                label = hf_result['label']
                score = hf_result['score']
                st.info(f"Probabilistic Model: **{label}** ({score:.1%})")
            elif hf_result.get("status") == "loading":
                 st.caption("⚠️ ML Model is warming up, proceeding with LLM only...")
            
            # 2. GROQ Reasoning
            user_prompt = PromptManager.format_phishing_prompt(email_subject, email_body, hf_result)
            system_prompt = PromptManager.get_system_prompt("phishing")
            
            result = groq_service.execute_prompt(user_prompt, system_prompt)
            
            if result["status"] == "success":
                # Save to History
                full_result = {
                    "hf_result": hf_result,
                    "groq_result": result
                }
                DatabaseService.save_scan("PHISHING", email_body[:50] + "...", full_result)

                st.success("Analysis Complete")
                st.markdown("### 🛡️ Threat Report")
                st.markdown(result["content"])

                # Report Download
                from services.report_service import ReportService
                report_md = ReportService.generate_markdown_report("PHISHING", email_body, full_result)
                st.download_button("📥 Download Analysis Report", report_md, file_name="phishing_report.md")
            else:
                st.error(f"Analysis Failed: {result['error']}")
