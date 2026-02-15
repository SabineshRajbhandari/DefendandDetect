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
                st.success("Analysis Complete")
                st.markdown("### 🛡️ Threat Report")
                st.markdown(result["content"])
            else:
                st.error(f"Analysis Failed: {result['error']}")
