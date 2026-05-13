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

if "restored_result" not in st.session_state:
    st.session_state.restored_result = None
if "selected_scans" not in st.session_state:
    st.session_state.selected_scans = set()

# Initialize Database
DatabaseService.init_db()

def load_css():
    with open("style.css") as f:
        css = f.read()
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
    st.markdown('<div class="scanlines"></div>', unsafe_allow_html=True)

def auto_collapse_sidebar():
    """
    Injects JS to automatically collapse the sidebar on mobile devices
    after a navigation event.
    """
    js = """
    <script>
    // Use a small timeout to ensure the Streamlit UI has rendered
    setTimeout(function() {
        var parentView = window.parent;
        if (!parentView) return;

        // Detect if parent window is mobile/tablet size
        if (parentView.innerWidth < 1024) {
            // Target elements in the parent document
            var buttons = parentView.document.getElementsByTagName('button');
            for (var i = 0; i < buttons.length; i++) {
                var btn = buttons[i];
                var aria = btn.getAttribute('aria-label');
                var testId = btn.getAttribute('data-testid');
                
                // Specifically target the "Close sidebar" button
                if (aria === "Close sidebar" || testId === "stSidebarCollapseButton") {
                    btn.click();
                    break;
                }
            }
        }
    }, 100); 
    </script>
    """
    st.components.v1.html(js, height=0, width=0)

def main():
    load_css()
    
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
        "File Hash Scanner": "🔍 HASH SCANNER",
        "CVE Explainer": "🛡️ CVE EXPLAINER",
        "Log Translator": "📝 LOG TRANSLATOR",
        "Breach Checker": "🗄️ BREACH CHECKER",
        "Compare Mode": "⚖️ COMPARE MODE",
        "Activity History": "📂 ACTIVITY HISTORY"
    }

    for page_name, icon_name in pages.items():
        # Highlight active button
        button_type = "primary" if st.session_state.page == page_name else "secondary"
        label = icon_name
        
        if st.sidebar.button(label, key=page_name, type=button_type, use_container_width=True):
            st.session_state.page = page_name
            st.session_state.restored_result = None # Clear restored result on nav
            
            # Clear all active (unsaved) results on navigation to prevent state leakage
            active_states = [
                "active_phish_result", "active_url_result", 
                "active_hash_result", "active_cve_result", 
                "active_log_result", "active_breach_result"
            ]
            for state in active_states:
                if state in st.session_state:
                    st.session_state[state] = None
            
            st.query_params["page"] = page_name  # Save to URL
            st.rerun() # Force reload to update UI immediately
    
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
    
    # Auto-collapse sidebar on mobile after navigation
    auto_collapse_sidebar()
    
    if module == "Home":
        show_home()
    elif module == "Phishing Detector":
        from modules.phishing import show_phishing_module
        show_phishing_module()
    elif module == "URL Analyzer":
        from modules.url_analyzer import show_url_analyzer
        show_url_analyzer()
    elif module == "File Hash Scanner":
        from modules.hash_scanner import show_hash_scanner
        show_hash_scanner()
    elif module == "CVE Explainer":
        from modules.cve_explainer import show_cve_module
        show_cve_module()
    elif module == "Log Translator":
        from modules.log_translator import show_log_module
        show_log_module()
    elif module == "Breach Checker":
        from modules.breach_checker import show_breach_module
        show_breach_module()
    elif module == "Compare Mode":
        from modules.compare_threats import show_compare_mode
        show_compare_mode()
    elif module == "Activity History":
        from modules.history_manager import show_history_manager
        show_history_manager()

def show_home():
    st.title("🛡️ DEFEND & DETECT")
    st.markdown("### AI-Powered Cybersecurity Education Platform")
    
    st.markdown("""
    Welcome to **Defend & Detect**, an educational platform designed to help you understand and mitigate cyber threats using AI.
    
    ### 🚀 Modules
    
    1. **📧 Phishing Detector**: Analyze suspicious emails and learn to spot red flags.
    2. **🔗 URL Analyzer**: Deconstruct malicious links and understand obfuscation techniques.
    3. **🛡️ CVE Explainer**: Translate complex vulnerability descriptions into plain English.
    4. **📝 Log Translator**: Decipher obscure server logs into actionable security insights.
    5. **🗄️ Breach Checker**: Scan passwords safely against known breach databases.
    6. **📂 Activity History**: Audit, manage, and export your personal security scan intelligence.
    
    ---
    *Powered by GROQ and Llama 3*
    """)

if __name__ == "__main__":
    main()
