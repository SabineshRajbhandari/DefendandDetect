import sys
import os
import requests

# Add the parent directory to sys.path so we can import our config and services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config

def check_groq():
    print("Checking Groq AI Service...")
    api_key = Config.get_groq_api_key()
    if not api_key:
        print("❌ Groq API Key is missing in .env")
        return False
    
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        response = requests.get("https://api.groq.com/openai/v1/models", headers=headers, timeout=10)
        if response.status_code == 200:
            print("✅ Groq Connection: SUCCESS")
            return True
        else:
            print(f"❌ Groq Connection: FAILED (Status: {response.status_code})")
            return False
    except Exception as e:
        print(f"❌ Groq Connection: ERROR ({str(e)})")
        return False

def check_virustotal():
    print("\nChecking VirusTotal Service...")
    api_key = Config.get_virustotal_api_key()
    if not api_key:
        print("❌ VirusTotal API Key is missing in .env")
        return False
    
    headers = {"x-apikey": api_key}
    try:
        response = requests.get("https://www.virustotal.com/api/v3/users/me", headers=headers, timeout=10)
        if response.status_code == 200:
            print("✅ VirusTotal Connection: SUCCESS")
            return True
        else:
            print(f"❌ VirusTotal Connection: FAILED (Status: {response.status_code})")
            return False
    except Exception as e:
        print(f"❌ VirusTotal Connection: ERROR ({str(e)})")
        return False

def check_huggingface():
    print("\nChecking HuggingFace Service...")
    api_key = Config.get_hf_api_key()
    if not api_key:
        print("⚠️  HuggingFace API Key is missing (Some models may still work via public inference)")
        return False
    
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        # Check a common model
        model_url = "https://api-inference.huggingface.co/models/mrm8488/bert-tiny-finetuned-sms-spam-detection"
        response = requests.get(model_url, headers=headers, timeout=10)
        if response.status_code != 401:
            print("✅ HuggingFace Connection: SUCCESS")
            return True
        else:
            print("❌ HuggingFace Connection: FAILED (Invalid Token)")
            return False
    except Exception as e:
        print(f"❌ HuggingFace Connection: ERROR ({str(e)})")
        return False

if __name__ == "__main__":
    print("=== Defend & Detect Service Diagnostic ===\n")
    check_groq()
    check_virustotal()
    check_huggingface()
    print("\n===========================================")
