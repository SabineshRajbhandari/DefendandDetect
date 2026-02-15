import streamlit as st
from services.groq_service import groq_service
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

    log_entry = st.text_area("Paste Log Entry", height=150, placeholder="Example: Feb 7 10:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 5000 ssh2")

    if st.button("Translate Log"):
        if not log_entry:
            st.warning("Please enter a log entry.")
            return

        with st.spinner("Decoding log syntax..."):
            user_prompt = PromptManager.format_log_prompt(log_entry)
            system_prompt = PromptManager.get_system_prompt("logs")
            
            result = groq_service.execute_prompt(user_prompt, system_prompt)
            
            if result["status"] == "success":
                st.success("Translation Complete")
                st.markdown("### 📊 Log Analysis")
                st.markdown(result["content"])
            else:
                st.error(f"Translation Failed: {result['error']}")
