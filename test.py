import os
import streamlit as st
from huggingface_hub import InferenceClient
from dotenv import load_dotenv

load_dotenv()

def main():
    st.title("Hugging Face Test")
    
    api_key = os.getenv("HF_API_KEY")
    if not api_key:
        st.error("HF_API_KEY not found in .env")
        return

    # Use a real model ID (e.g., text classification for phishing)
    model_id = "fmeyer/deep-phish-detection" 
    
    st.write(f"Testing Model: `{model_id}`")
    
    text_input = st.text_input("Enter text to classify", "http://suspicious-url.com/login")
    
    if st.button("Run Inference"):
        try:
            client = InferenceClient(token=api_key)
            result = client.text_classification(text_input, model=model_id)
            st.json(result)
        except Exception as e:
            st.error(f"Error: {e}")

if __name__ == "__main__":
    main()
