import streamlit as st
import importlib
from services.huggingface_service import HuggingFaceService
from services.virustotal_service import VirusTotalService
from services.groq_service import GroqService
from prompts import PromptManager
import validators

def show_url_module():
    st.header("🔗 Malicious URL Analyzer")
    st.markdown("Deconstruct suspicious links using **VirusTotal** reputation + **Hugging Face** structural analysis.")
    
    from services.database_service import DatabaseService

    # Check for restored history
    if st.session_state.get("restored_result") and st.session_state.restored_result["type"] == "URL":
        res = st.session_state.restored_result
        st.info(f"📜 Showing History from: {res['timestamp']}")
        
        url_input = st.text_input("Suspicious URL", value=res['input'], disabled=True)
        
        result_data = res['result']
        vt_result = result_data.get('vt_result', {})
        hf_result = result_data.get('hf_result', {})
        final_analysis = result_data.get('final_analysis', {})
        
        # Display Results Logic (Duplicated for simplicity, ideally refactored)
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("VirusTotal Reputation")
            if vt_result.get("status") == "success":
                if vt_result.get("is_malicious"):
                    st.error(f"🚨 MALICIOUS ({vt_result['stats']['malicious']} vendors)")
                else:
                    st.success("✅ Clean / Unlisted")
                if "stats" in vt_result:
                    st.json(vt_result["stats"])
        with col2:
             st.subheader("Structural Analysis")
             if hf_result.get("status") == "success":
                label = hf_result.get("label")
                score = hf_result.get("score")
                color = "red" if label == "MALICIOUS" else "green"
                st.markdown(f"**Prediction:** :{color}[{label}]")
                st.progress(score, text=f"Confidence: {score:.2%}")
        
        st.markdown("### 🧠 Synthesis")
        if final_analysis.get("status") == "success":
             st.markdown(final_analysis["content"])
             
             # Report Download
             from services.report_service import ReportService
             report_md = ReportService.generate_markdown_report("URL", res['input'], result_data)
             st.download_button("📥 Download Analysis Report", report_md, file_name=f"url_report_{res['id']}.md")
             
        if st.button("Start New Scan"):
             st.session_state.restored_result = None
             st.rerun()
        return

    url_input = st.text_input("Enter Suspicious URL:", placeholder="http://login-update-security.com")
    
    if st.button("Analyze URL"):
        if not validators.url(url_input):
            st.error("Invalid URL format. Please include http:// or https://")
            return

        with st.spinner("Scanning global threat databases..."):
            # 1. VirusTotal Check
            vt_result = VirusTotalService.check_url(url_input)
            
            # 2. AI Classification (Hugging Face)
            hf_result = HuggingFaceService.classify_url(url_input)
            
            # 3. GROQ Synthesis
            groq = GroqService()
            prompt = PromptManager.format_url_prompt(url_input, vt_result, hf_result)
            final_analysis = groq.execute_prompt(prompt)

            # Display Results
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("VirusTotal Reputation")
                if vt_result.get("status") == "success":
                    if vt_result.get("is_malicious"):
                        st.error(f"🚨 MALICIOUS ({vt_result['stats']['malicious']} vendors)")
                    else:
                        st.success("✅ Clean / Unlisted")
                    if "stats" in vt_result:
                        st.json(vt_result["stats"])
                else:
                    st.warning(f"Check Failed: {vt_result.get('message')}")

            with col2:
                st.subheader("Structural Analysis")
                if hf_result.get("status") == "success":
                    label = hf_result.get("label")
                    score = hf_result.get("score")
                    color = "red" if label == "MALICIOUS" else "green"
                    st.markdown(f"**Prediction:** :{color}[{label}]")
                    st.progress(score, text=f"Confidence: {score:.2%}")
                else:
                    st.warning("AI Analysis Unavailable")

            st.markdown("### 🧠 Synthesis")
            if final_analysis["status"] == "success":
                if final_analysis.get("thought"):
                    with st.expander("🧠 AI Thinking Process"):
                        st.write(final_analysis["thought"])
                
                # Save to History
                full_result = {
                    "vt_result": vt_result,
                    "hf_result": hf_result,
                    "final_analysis": final_analysis
                }
                DatabaseService.save_scan("URL", url_input, full_result)
                
                st.markdown(final_analysis["content"])

                # Report Download
                from services.report_service import ReportService
                report_md = ReportService.generate_markdown_report("URL", url_input, full_result)
                st.download_button("📥 Download Analysis Report", report_md, file_name="url_report.md")
            else:
                st.error("Synthesis failed.")
