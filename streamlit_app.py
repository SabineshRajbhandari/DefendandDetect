import streamlit as st
from config import Config
from services.groq_service import groq_service

from services.database_service import DatabaseService

# Page Configuration
st.set_page_config(
    page_title=Config.APP_NAME,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize Session State
if "history" not in st.session_state:
    st.session_state.history = []
if "restored_result" not in st.session_state:
    st.session_state.restored_result = None

# Initialize Database
DatabaseService.init_db()

def load_css():
    with open("style.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

def main():
    st.title(f"🛡️ {Config.APP_NAME}")
    st.markdown("### AI-Powered Cybersecurity Education Platform")
    
    # Sidebar Navigation
    st.sidebar.title("Navigation")
    
    # Sync session state with query parameters for persistence
    if "page" not in st.session_state:
        query_page = st.query_params.get("page", "Home")
        st.session_state.page = query_page

    # Navigation Buttons
    pages = {
        "Home": "🏠 DASHBOARD",
        "Phishing Detector": "📧 PHISHING DETECTOR",
        "URL Analyzer": "🔗 URL ANALYZER",
        "CVE Explainer": "🛡️ CVE EXPLAINER",
        "Log Translator": "📝 LOG TRANSLATOR"
    }

    for page_name, icon_name in pages.items():
        # Highlight active button
        button_type = "primary" if st.session_state.page == page_name else "secondary"
        label = f"➤ {icon_name}" if st.session_state.page == page_name else icon_name
        
        if st.sidebar.button(label, key=page_name, type=button_type, use_container_width=True):
            st.session_state.page = page_name
            st.session_state.restored_result = None # Clear restored result on nav
            st.query_params["page"] = page_name  # Save to URL
            st.rerun() # Force reload to update UI immediately
    
    st.sidebar.markdown("---")
    
    # History Sidebar
    with st.sidebar.expander("📜 Recent Activity", expanded=True):
        recent_scans = DatabaseService.get_recent_scans()
        if not recent_scans:
            st.info("No recent scans.")
        else:
            for scan in recent_scans:
                label = f"[{scan['type']}] {scan['timestamp'].split(' ')[1]}"
                if st.button(label, key=f"hist_{scan['id']}", help=scan['input']):
                    st.session_state.restored_result = scan
                    # Navigate to correct page
                    page_map = {
                        "PHISHING": "Phishing Detector",
                        "URL": "URL Analyzer",
                        "CVE": "CVE Explainer",
                        "LOG": "Log Translator"
                    }
                    if scan['type'] in page_map:
                        st.session_state.page = page_map[scan['type']]
                        st.query_params["page"] = st.session_state.page
                        st.rerun()
            
            if st.button("🗑️ Clear History"):
                DatabaseService.clear_history()
                st.rerun()

    st.sidebar.markdown("---")
    
    # API Key Configuration in Sidebar (if not in env)
    if not Config.get_groq_api_key():
        st.sidebar.warning("⚠️ API Key Missing")
        api_key_input = st.sidebar.text_input("Enter GROQ API Key:", type="password")
        if api_key_input:
            # In a real app, we might handle this differently, but for now we rely on config
            # This is just a UI placeholder to show we handle missing keys
            st.sidebar.info("Please add this key to your .env file or Streamlit secrets.")
    else:
        st.sidebar.success("✅ SYSTEM ONLINE")

    # Routing
    module = st.session_state.page
    
    if module == "Home":
        show_home()
    elif module == "Phishing Detector":
        from modules.phishing import show_phishing_module
        show_phishing_module()
    elif module == "URL Analyzer":
        from modules.url_analyzer import show_url_module
        show_url_module()
    elif module == "CVE Explainer":
        from modules.cve_explainer import show_cve_module
        show_cve_module()
    elif module == "Log Translator":
        from modules.log_translator import show_log_module
        show_log_module()

def show_home():
    st.markdown("""
    Welcome to **Defend & Detect**, an educational platform designed to help you understand and mitigate cyber threats using AI.
    
    ### 🚀 Modules
    
    1. **📧 Phishing Detector**: Analyze suspicious emails and learn to spot red flags.
    2. **🔗 URL Analyzer**: Deconstruct malicious links and understand obfuscation techniques.
    3. **🛡️ CVE Explainer**: Translate complex vulnerability descriptions into plain English.
    4. **📝 Log Translator**: Decipher obscure server logs into actionable security insights.
    
    ---
    *Powered by GROQ and Llama 3*
    """)

if __name__ == "__main__":
    main()
