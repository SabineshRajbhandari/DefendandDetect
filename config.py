import os
import streamlit as st
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """
    Central configuration for Defend & Detect.
    """
    
    # -------------------------------------------------------------------------
    # API Configuration
    # -------------------------------------------------------------------------
    _GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    
    @classmethod
    def get_groq_api_key(cls):
        """
        Securely retrieve the GROQ API key.
        Prioritizes environment variables, then checks Streamlit secrets (for cloud deployment).
        """
        if cls._GROQ_API_KEY:
            return cls._GROQ_API_KEY
        
        # Fallback for Streamlit Cloud
        if "GROQ_API_KEY" in st.secrets:
            return st.secrets["GROQ_API_KEY"]
            
        return None

    # -------------------------------------------------------------------------
    # Hugging Face Configuration
    # -------------------------------------------------------------------------
    _HF_API_KEY = os.getenv("HF_API_KEY")
    
    @classmethod
    def get_hf_api_key(cls):
        if cls._HF_API_KEY: return cls._HF_API_KEY
        if "HF_API_KEY" in st.secrets: return st.secrets["HF_API_KEY"]
        return None

    # Models
    HF_PHISHING_MODEL = "fmeyer/deep-phish-detection"
    HF_URL_MODEL = "sid321axn/bert-base-uncased-url-phishing"

    # -------------------------------------------------------------------------
    # NVD Configuration
    # -------------------------------------------------------------------------
    _NVD_API_KEY = os.getenv("NVD_API_KEY")

    @classmethod
    def get_nvd_api_key(cls):
        if cls._NVD_API_KEY: return cls._NVD_API_KEY
        if "NVD_API_KEY" in st.secrets: return st.secrets["NVD_API_KEY"]
        return None

    # -------------------------------------------------------------------------
    # VirusTotal Configuration
    # -------------------------------------------------------------------------
    _VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

    @classmethod
    def get_virustotal_api_key(cls):
        if cls._VIRUSTOTAL_API_KEY: return cls._VIRUSTOTAL_API_KEY
        if "VIRUSTOTAL_API_KEY" in st.secrets: return st.secrets["VIRUSTOTAL_API_KEY"]
        return None

    @property
    def VIRUSTOTAL_API_KEY(cls):
        return cls.get_virustotal_api_key()

    # -------------------------------------------------------------------------
    # Model Settings
    # -------------------------------------------------------------------------
    # Reverting to Llama 3.3 70b (Versatile) as DeepSeek-R1 was decommissioned.
    # We will use explicit prompting to maintain the 'Intelligence Thinking' experience.
    MODEL_NAME = "llama-3.3-70b-versatile" 
    
    # Fallback model for faster/lighter queries if needed
    FAST_MODEL_NAME = "llama-3.1-8b-instant"

    # Inference parameters
    TEMPERATURE = 0.3  # Low temperature for factual/analytical consistency
    MAX_TOKENS = 1024  # Sufficient for detailed explanations
    
    # -------------------------------------------------------------------------
    # Application Settings
    # -------------------------------------------------------------------------
    APP_NAME = "Defend & Detect"
    VERSION = "1.6.0"
    
    # Retry settings
    MAX_RETRIES = 3
    RETRY_DELAY = 1  # Seconds
