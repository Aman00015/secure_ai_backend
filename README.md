# sentinelOps Backend (SecureAI API)

A high-performance FastAPI cybersecurity backend powering the **sentinelOps** (SecureAI) platform. The service provides repository dependency vulnerability scanning, AI-driven remediation guidance via Google Gemini, machine-learning-based phishing URL detection, high-concurrency subdomain discovery, and static Windows PE malware analysis.

---

## 🚀 Features

- **🔍 Automated Dependency Vulnerability Scanner**
  - Clones public GitHub repositories in an isolated workspace (`git clone --depth 1`).
  - Automatically identifies project ecosystems and manifests (Python `requirements.txt`, Node.js `package.json`, etc.).
  - Executes security audits (`pip-audit`, `npm audit`, `osv-scanner`) and standardizes vulnerability reports with CVE/PYSEC identifiers, severity levels (Critical, High, Medium, Low), and advisory links.

- **🤖 AI-Powered Security Fix Generator**
  - Integrates with **Google Gemini 2.5 Flash** to analyze vulnerabilities and CVE advisories.
  - Generates clear, structured Markdown remediation playbooks including immediate mitigation steps, code patches, version upgrades, and temporary workarounds.

- **🛡️ Machine Learning Phishing URL Detector**
  - Analyzes incoming URLs across 30 distinct heuristic, structural, and DNS features (IP address usage, URL shortening, SSL certificate age, domain registration length, anchor URL ratios, Google indexing status, and traffic metrics).
  - Uses a pre-trained **Random Forest Classifier** (`phishing_model.pkl`) to output real-time threat classifications and feature breakdowns.

- **🌐 Asynchronous Subdomain Discovery**
  - High-speed subdomain enumeration combining Certificate Transparency log lookups (`crt.sh`), curated wordlist brute-forcing, asynchronous DNS resolution, and live HTTP/HTTPS status verification using `aiohttp`.

- **🔬 Windows PE Malware Analyzer**
  - Performs static inspection of Portable Executable files (`.exe`, `.dll`, `.sys`, `.scr`, `.ocx`).
  - Extracts 54 structural header attributes (Shannon entropy per section and resource, import table metrics, PE section count, checksum validity) and predicts classification with plain-English risk signal explanations.

---

## 📁 Repository Structure

```text
securi-ai-backend/
├── main.py                   # FastAPI application initialization & CORS middleware
├── routes.py                 # Core API endpoints & model lifecycle management
├── subdomain_finder.py       # Async subdomain enumeration router & DNS/HTTP scanner
├── phishing_detector.py      # 30-feature URL extraction engine & Random Forest detector
├── phishing_model.pkl        # Trained Random Forest model for phishing detection
├── pe_scanner.py             # Windows PE static feature extractor & Random Forest scanner
├── scanner_router.py         # Subprocess runner for language-specific vulnerability audits
├── train_phishing_model.py   # Training script for phishing detection model
├── Training Dataset.arff     # ARFF dataset used for phishing model training
├── Procfile                  # Production server command for Render deployment
├── requirements.txt          # Python dependencies
├── README.md                 # Primary documentation
├── README_RENDER.md          # Cloud deployment guide for Render
└── utils/
    ├── cve_parser.py         # Advisory URL parsing, CIRCL lookup, severity normalization
    └── repo_manager.py       # GitHub clone management & language/manifest detection
```

---

## 🛠️ Tech Stack

- **Framework**: [FastAPI](https://fastapi.tiangolo.com/) + [Pydantic](https://docs.pydantic.dev/)
- **Server**: [Uvicorn](https://www.uvicorn.org/) (Local Dev) / [Gunicorn](https://gunicorn.org/) with Uvicorn workers (Production)
- **Machine Learning**: [scikit-learn](https://scikit-learn.org/), [pandas](https://pandas.pydata.org/), [scipy](https://scipy.org/), [joblib](https://joblib.readthedocs.io/)
- **Security Auditing**: [pip-audit](https://pypi.org/project/pip-audit/), [pefile](https://github.com/erocarrera/pefile), `npm audit`
- **Generative AI**: [Google Generative AI SDK](https://pypi.org/project/google-generativeai/) (`gemini-2.5-flash`)
- **Web & DNS Utilities**: `aiohttp`, `dnspython`, `beautifulsoup4`, `tldextract`, `python-whois`

---

## ⚙️ Installation & Local Setup

### Prerequisites

- **Python 3.9+** (Python 3.9 or 3.10 recommended)
- **Git** installed and available in your `PATH`
- **Node.js & npm** (optional, required if auditing Node.js repositories locally)

### 1. Clone & Navigate to Backend

```bash
git clone <repository-url>
cd "securi-ai backend"
```

### 2. Create and Activate Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the Development Server

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Once running, the interactive OpenAPI documentation is available at:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 📡 API Reference

### Health Checks

#### `GET /`
Basic root status check.
```json
{
  "message": "Security AI Scanner API is running!"
}
```

#### `GET /health`
Service health check.
```json
{
  "status": "ok"
}
```

---

### Vulnerability Scanner

#### `POST /scan`
Clones a public GitHub repository and scans its dependency manifests for known CVEs.

- **Request Body:**
  ```json
  {
    "repo_url": "https://github.com/psf/requests"
  }
  ```
- **Response Example:**
  ```json
  {
    "repo_url": "https://github.com/psf/requests",
    "language": "python",
    "scan_results": [
      {
        "package": "certifi",
        "installed_version": "2021.5.30",
        "vulnerability_id": "CVE-2022-23491",
        "severity": "high",
        "fixed_version": "2022.12.07",
        "description": "Certifi root certificates untrusted root removal...",
        "advisory_url": "https://github.com/advisories/GHSA-x345-32wf-mjfw"
      }
    ]
  }
  ```

---

### AI Security Fix Generator

#### `POST /api/generate-fix`
Uses Google Gemini 2.5 Flash to analyze a vulnerability URL and provide a formatted Markdown remediation guide.

- **Request Body:**
  ```json
  {
    "cveUrl": "https://github.com/pypa/advisory-database/blob/main/vulns/cryptography/PYSEC-2023-11.md",
    "apiKey": "YOUR_GEMINI_API_KEY"
  }
  ```
- **Response Structure:**
  ```json
  {
    "fixes": "# 🔍 Vulnerability Analysis\n...",
    "workarounds": "Detailed temporary workarounds...",
    "model_used": "gemini-2.5-flash",
    "formatted": true
  }
  ```

---

### Phishing Detection

#### `POST /phishing/check`
Extracts 30 URL features and evaluates whether a URL is legitimate or a phishing attempt.

- **Request Body:**
  ```json
  {
    "url": "https://paypal-security-update.suspicious-domain.com"
  }
  ```
- **Response Structure:**
  ```json
  {
    "success": true,
    "result": {
      "prediction": -1,
      "prediction_text": "Phishing",
      "probability": 94.2,
      "features": {
        "having_IP_Address": 1,
        "URL_Length": -1,
        "SSLfinal_State": -1
      }
    }
  }
  ```

#### `GET /phishing/health`
Checks if the phishing model (`phishing_model.pkl`) is loaded in memory.

---

### Subdomain Discovery

#### `POST /find-subdomains`
Discovers live subdomains using Certificate Transparency logs and concurrent DNS/HTTP probing.

- **Request Body:**
  ```json
  {
    "domain": "example.com"
  }
  ```
- **Response Example:**
  ```json
  {
    "domain": "example.com",
    "subdomains": [
      {
        "subdomain": "api.example.com",
        "status": "active",
        "http_status": 200,
        "protocol": "https"
      }
    ],
    "total_found": 1,
    "scan_methods": ["crt.sh", "wordlist", "dns_resolution"]
  }
  ```

---

### PE Malware Scanner

#### `POST /malware/scan`
Upload a Windows executable (`.exe`, `.dll`, `.sys`, `.scr`, `.ocx`) to inspect PE header characteristics and predict classification.

- **Form Data:** `file`: `[binary data]`
- **Response Example:**
  ```json
  {
    "success": true,
    "filename": "sample.exe",
    "result": {
      "verdict": "malware",
      "confidence": 98.4,
      "features": {
        "SectionsMaxEntropy": 7.82,
        "ImportsNbDLL": 14,
        "CheckSum": 0
      },
      "risk_signals": [
        "High section entropy (7.82/8.0) — file sections appear packed or encrypted.",
        "CheckSum is zero — unsigned or modified binary."
      ]
    }
  }
  ```

#### `GET /malware/health`
Checks whether the PE malware classifier and feature lists are loaded.

---

## 🚢 Production Deployment (Render)

This repository is ready to deploy directly on [Render](https://render.com) as a Web Service.

1. **Create Web Service**:
   - Connect the repository on Render.
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT` (or leave empty to use [`Procfile`](file:///c:/Users/mansu/Documents/Next%20Projects/secureai/securi-ai%20backend/Procfile))
2. **Environment Variables**:
   - `GEMINI_API_KEY`: (Optional default key if not provided per-request)
   - `PORT`: (Injected automatically by Render)
3. **Health Check Path**: `/health`

For more details, see [`README_RENDER.md`](file:///c:/Users/mansu/Documents/Next%20Projects/secureai/securi-ai%20backend/README_RENDER.md).

---

## 🔒 Security & Safe Usage

- Cloned repositories are downloaded shallowly (`--depth 1`) into isolated temporary directories and cleaned up following analysis.
- Executable files submitted to `/malware/scan` are stored in ephemeral temporary storage and removed immediately after header feature extraction.
- CORS is enabled for frontend integrations. For production-only deployments, restrict `allow_origins` in [`main.py`](file:///c:/Users/mansu/Documents/Next%20Projects/secureai/securi-ai%20backend/main.py) to trusted frontend domains.
