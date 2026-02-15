import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_URL = "https://api-inference.huggingface.co/models/sid321axn/bert-base-uncased-url-phishing"
API_KEY = os.getenv("HF_API_KEY")

def test_hf():
    print(f"Testing HF API with Key: {API_KEY[:4]}...{API_KEY[-4:] if API_KEY else 'NONE'}")
    
    headers = {"Authorization": f"Bearer {API_KEY}"}
    payload = {"inputs": "http://google.com"}
    
    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_hf()
