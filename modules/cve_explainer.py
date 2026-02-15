import streamlit as st
from services.groq_service import groq_service
from prompts import PromptManager

def show_cve_module():
    st.header("🛡️ CVE Vulnerability Explainer")
    st.markdown("Translate complex CVE descriptions into plain English for better understanding.")

    with st.expander("ℹ️ How it works"):
        st.markdown("""
        Takes a CVE ID (e.g., CVE-2021-44228) and provides:
        - Real-world impact analysis
        - Severity context
        - Mitigation strategies
        """)

    cve_id = st.text_input("CVE ID", placeholder="CVE-2021-44228")

    if st.button("Explain Vulnerability"):
        if not cve_id:
            st.warning("Please enter a CVE ID.")
            return

        with st.spinner("Fetching official NVD data..."):
            # 1. Fetch NVD Data
            from services.nvd_service import nvd_service
            nvd_result = nvd_service.fetch_cve(cve_id)
            
            if nvd_result.get("status") == "success":
                st.info(f"**Official Data Found**: {nvd_result['id']} (Severity: {nvd_result['severity']} - {nvd_result['score']})")
                with st.expander("Show Official Description"):
                    st.write(nvd_result['description'])
            elif nvd_result.get("status") == "not_found":
                st.warning("CVE ID not found in NVD database. Proceeding with general knowledge...")
            
            # 2. GROQ Explain
            user_prompt = PromptManager.format_cve_prompt(cve_id, nvd_result)
            system_prompt = PromptManager.get_system_prompt("cve")
            
            result = groq_service.execute_prompt(user_prompt, system_prompt)
            
            if result["status"] == "success":
                st.success("Explanation Generated")
                st.markdown("### 📖 Vulnerability Insight")
                st.markdown(result["content"])
            else:
                st.error(f"Explanation Failed: {result['error']}")
