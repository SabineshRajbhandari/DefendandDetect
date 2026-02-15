# 🛡️ Defend & Detect: AI-Powered Cybersecurity Platform

**Defend & Detect** is an educational cybersecurity tool designed to help users analyze and understand digital threats. It combines real-time threat intelligence APIs with Generative AI to provide clear, actionable explanations for complex security events.

---

## 🚀 Features

### 1. 📧 Phishing Detector
- **Analyze Emails**: detects social engineering tactics in email subjects and bodies.
- **Hybrid Analysis**: Uses **Hugging Face** (BERT) for probability scoring and **GROQ** (Llama 3) for explanatory reasoning.

### 2. 🔗 Malicious URL Analyzer
- **Link Deconstruction**: Breaks down suspicious URLs without visiting them.
- **Multi-layered Scanner**:
    - **VirusTotal API**: Checks reputation against 70+ security vendors.
    - **AI Heuristics**: Analyzes URL structure for obfuscation and typosquatting.
    - **Synthesis**: Generates a unified safety report.

### 3. 🛡️ CVE Explainer
- **Vulnerability Intelligence**: Translates technical CVE IDs (e.g., `CVE-2023-44487`) into plain English.
- **Official Data**: Fetches real-time metadata from the **NIST NVD API**.
- **Risk Assessment**: Explains severity, impact, and mitigation steps.

### 4. 📝 Log Translator
- **Error Decoding**: Converts obscure server logs and error codes into human-readable insights.
- **Actionable Advice**: Suggests immediate steps to resolve the issue.

---

## 🛠️ Architecture

The platform is built on a modular micro-service architecture:

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Frontend** | Streamlit | Interactive web UI |
| **Reasoning Engine** | GROQ API (Llama 3.3) | Natural language explanation & synthesis |
| **ML Models** | Hugging Face (BERT) | Probability scoring for Phishing/URLs |
| **Threat Intel** | VirusTotal API | Real-time URL/Domain reputation |
| **Vuln Data** | NIST NVD API | Official CVE metadata |

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- API Keys for: **GROQ**, **Hugging Face**, **VirusTotal**, **NVD** (Optional)

### Setup

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/SabineshRajbhandari/DefendandDetect.git
    cd DefendandDetect
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure Environment**
    - Copy the example environment file:
        ```bash
        cp .env.example .env
        ```
    - Open `.env` and add your API keys:
        ```ini
        GROQ_API_KEY=gsk_...
        HF_API_KEY=hf_...
        VIRUSTOTAL_API_KEY=...
        NVD_API_KEY=...
        ```

4.  **Run the Application**
    ```bash
    streamlit run streamlit_app.py
    ```

---

## 📂 Project Structure

```
defend-and-detect/
├── modules/                # Core functional modules
│   ├── phishing.py         # Email analysis logic
│   ├── url_analyzer.py     # URL scanning logic
│   ├── cve_explainer.py    # CVE fetching & explanation
│   └── log_translator.py   # Log parsing
├── services/               # API Integration layers
│   ├── groq_service.py     # LLM interaction
│   ├── hugginface_service.py # ML model inference
│   ├── virustotal_service.py # Reputation checking
│   └── nvd_service.py      # NIST data fetching
├── assets/                 # Static assets (images, css)
├── config.py               # Central configuration
├── streamlit_app.py        # Main entry point & UI routing
└── requirements.txt        # Python dependencies
```

---

## 🤝 Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.
