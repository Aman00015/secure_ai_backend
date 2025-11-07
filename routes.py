from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import logging
import google.generativeai as genai
from phishing_detector import phishing_detector
import os
from subdomain_finder import router as subdomain_router

logger = logging.getLogger(__name__)
router = APIRouter()

# Include the subdomain router WITHOUT prefix to match your frontend request
router.include_router(subdomain_router, tags=["subdomain"])

# REQUEST MODELS
class ScanRequest(BaseModel):
    repo_url: str

class GenerateFixRequest(BaseModel):
    cveUrl: str
    apiKey: str

class PhishingCheckRequest(BaseModel):
    url: str

# Initialize phishing detector
@router.on_event("startup")
async def startup_event():
    try:
        model_path = "phishing_model.pkl"
        if os.path.exists(model_path):
            phishing_detector.load_model(model_path)
            logger.info("Phishing detection model loaded successfully")
        else:
            logger.warning("Phishing model file not found. Phishing detection will not work.")
    except Exception as e:
        logger.warning(f"Could not load phishing model: {str(e)}")

# Health check
@router.get("/health")
def health_check():
    return {"status": "ok"}

# Phishing detection route
@router.post("/phishing/check")
async def check_phishing(request: PhishingCheckRequest):
    try:
        logger.info(f"Checking URL for phishing: {request.url}")
        
        if phishing_detector.model is None:
            raise HTTPException(
                status_code=503,
                detail="Phishing detection service is not available. Model not loaded."
            )
        
        result = phishing_detector.predict(request.url)
        
        return {
            "success": True,
            "result": result
        }
        
    except Exception as e:
        logger.error(f"Phishing check error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to analyze URL: {str(e)}"
        )

# Health check for phishing service
@router.get("/phishing/health")
async def phishing_health():
    return {
        "status": "ok",
        "model_loaded": phishing_detector.model is not None,
        "service": "phishing_detection"
    }

# Repo scanning route
@router.post("/scan")
def scan_repo(request: ScanRequest):
    try:
        from utils.repo_manager import RepoManager
        from utils.cve_parser import CVEParser
        from scanner_router import ScannerRouter
        
        manager = RepoManager()
        scanner = ScannerRouter()
        parser = CVEParser()
        language = None
        repo_path = None

        logger.info(f"Starting scan for repository: {request.repo_url}")
        repo_path = manager.clone_repo(request.repo_url)
        language, manifest_path = manager.detect_language(repo_path)

        if language == "unknown" or not manifest_path:
            logger.warning(f"Unsupported or undetected language for {request.repo_url}")
            return {
                "repo_url": request.repo_url,
                "language": language,
                "scan_results": None,
                "error": {
                    "type": "LanguageDetectionError",
                    "message": "Unsupported or undetected language. Please ensure the repository contains a supported manifest file (e.g., requirements.txt, package.json).",
                    "step": "language_detection"
                }
            }

        logger.info(f"Running scan for {language} project")
        scan_results = scanner.run_scan(manifest_path, language)
        normalized_results = parser.normalize(scan_results)

        return {
            "repo_url": request.repo_url,
            "language": language,
            "scan_results": normalized_results
        }

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return {
            "repo_url": request.repo_url,
            "language": language,
            "scan_results": None,
            "error": {
                "type": e.__class__.__name__,
                "message": str(e),
                "step": "scanning"
            }
        }

@router.post("/api/generate-fix")
async def generate_fix(request: GenerateFixRequest):
    try:
        # Configure Gemini with user's API key
        genai.configure(api_key=request.apiKey)
        
        # Use Gemini Pro model
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        # More strict prompt with formatting requirements
        prompt = f"""
        You are a cybersecurity expert. Analyze this CVE/vulnerability and provide specific fixes in PROPER MARKDOWN format.
        
        Vulnerability URL: {request.cveUrl}
        
        CRITICAL: You MUST format your response using proper markdown syntax with clear sections. Do NOT use plain text without formatting.

        Structure your response exactly like this:

        # 🔍 Vulnerability Analysis
        [Provide a clear overview of the vulnerability, its impact, and affected components]

        # 🛡️ Immediate Mitigation Steps
        - [Step 1: Specific actionable step]
        - [Step 2: Specific actionable step] 
        - [Step 3: Specific actionable step]

        # 💻 Code Fixes
        [Provide specific code changes if applicable. Use proper code blocks with language specification]

        ```javascript
        // Example: Fix for JavaScript vulnerability
        const safeFunction = () => {{
          // Fixed code here
        }};
        ```

        # 📦 Version Upgrades
        - **Package**: current_version → safe_version
        - **Command**: `npm install package@safe_version`
        - **Alternative**: `pip install package==safe_version`

        # 🔒 Security Best Practices
        - [Best practice 1 with explanation]
        - [Best practice 2 with explanation]
        - [Best practice 3 with explanation]

        # ⚡ Temporary Workarounds
        - [Workaround 1: Specific temporary solution]
        - [Workaround 2: Specific temporary solution]

        Ensure every section uses proper markdown headers (## for main sections), bullet points (-), code blocks (```language), and bold text (**text**) where appropriate.
        Do not leave incomplete sentences or broken formatting.
        """

        # Generate response with stricter configuration
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.2,  # Lower temperature for more consistent formatting
                top_p=0.8,
                top_k=40,
                max_output_tokens=2048,
            )
        )
        
        content = response.text
        
        # Clean up the response - ensure proper markdown
        content = content.replace('** ', '**').replace(' **', '**')
        content = content.replace('``` ', '```').replace(' ```', '```')
        
        # Extract workarounds section
        workarounds = "See detailed workarounds in the fixes section above"
        if "## ⚡ Temporary Workarounds" in content or "# ⚡ Temporary Workarounds" in content:
            if "## ⚡ Temporary Workarounds" in content:
                sections = content.split("## ⚡ Temporary Workarounds")
            else:
                sections = content.split("# ⚡ Temporary Workarounds")
                
            if len(sections) > 1:
                workarounds_section = sections[1].split("##")[0] if "##" in sections[1] else sections[1]
                workarounds_section = workarounds_section.split("#")[0] if "#" in workarounds_section else workarounds_section
                workarounds = workarounds_section.strip()

        return {
            "fixes": content,
            "workarounds": workarounds,
            "model_used": "gemini-2.5-flash",
            "formatted": True
        }
        
    except Exception as e:
        logger.error(f"Gemini API error: {str(e)}")
        # Return a formatted error message
        error_content = """
# 🔍 Error Generating Fixes

We encountered an issue generating AI-powered fixes for this vulnerability.

## 🛠️ Manual Steps
- Check the CVE details in the provided link
- Review the vulnerability description above
- Consult the package documentation for security updates
- Consider upgrading to the latest secure version

## 🔒 General Security Practices
- Always keep dependencies updated
- Use security scanning tools regularly
- Follow the principle of least privilege
- Implement proper input validation
        """
        
        return {
            "fixes": error_content,
            "workarounds": "Please check the CVE details manually for workarounds",
            "model_used": "Error",
            "formatted": True
        }