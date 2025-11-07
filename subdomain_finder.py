import asyncio
import aiohttp
import dns.resolver
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import logging
from typing import List, Dict, Optional
import requests
import re

logger = logging.getLogger(__name__)
router = APIRouter()

class SubdomainRequest(BaseModel):
    domain: str

class SubdomainResult(BaseModel):
    subdomain: str
    status: str
    http_status: Optional[int] = None
    protocol: Optional[str] = None

class SubdomainResponse(BaseModel):
    domain: str
    subdomains: List[SubdomainResult]
    total_found: int
    scan_methods: List[str]

# Common subdomain wordlist
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
    'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
    'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs',
    'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media',
    'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2',
    'api', 'cdn', 'stats', 'dns1', 'ns4', 'mysql', 'files', 'host', 'ssl', 'preview',
    'dns', 'search', 'staging', 'server', 'devel', 'upload', 'backup', 'mx2', 'lyncdiscover',
    'meet', 'portal', 'apps', 'office', 'exchange', 'imaps', 'test', 'autodiscover',
    'storage', 'remote', 'db', 'owa', 'proxy', 'sharepoint', 'developer', 'reports',
    'app', 'live', 'adfs', 'monitor', 'help', 'sms', 'chat', 'docs', 'events', 'archive'
]

async def check_subdomain_exists(session: aiohttp.ClientSession, subdomain: str) -> SubdomainResult:
    """Check if a subdomain exists and is reachable"""
    try:
        # Try HTTP
        async with session.get(f"http://{subdomain}", timeout=5, ssl=False) as response:
            if response.status in [200, 301, 302, 403, 401]:
                return SubdomainResult(
                    subdomain=subdomain,
                    status="active",
                    http_status=response.status,
                    protocol="http"
                )
    except:
        pass
    
    try:
        # Try HTTPS
        async with session.get(f"https://{subdomain}", timeout=5, ssl=False) as response:
            if response.status in [200, 301, 302, 403, 401]:
                return SubdomainResult(
                    subdomain=subdomain,
                    status="active",
                    http_status=response.status,
                    protocol="https"
                )
    except:
        pass
    
    # Check DNS record
    try:
        dns.resolver.resolve(subdomain, 'A')
        return SubdomainResult(
            subdomain=subdomain,
            status="dns_only",
            http_status=None,
            protocol=None
        )
    except:
        return SubdomainResult(
            subdomain=subdomain,
            status="inactive",
            http_status=None,
            protocol=None
        )

async def find_subdoms_crt_sh(domain: str) -> List[str]:
    """Use crt.sh certificate transparency logs to find subdomains"""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = set()
                    for cert in data:
                        common_name = cert.get('common_name', '')
                        if common_name and domain in common_name:
                            subdomains.add(common_name)
                    return list(subdomains)
    except Exception as e:
        logger.warning(f"crt.sh API error: {e}")
    return []

async def find_subdoms_securitytrails(domain: str) -> List[str]:
    """Use SecurityTrails API (free tier)"""
    try:
        # Note: You'll need to get a free API key from securitytrails.com
        api_key = "YOUR_SECURITYTRAILS_API_KEY"  # Replace with actual API key
        if api_key == "YOUR_SECURITYTRAILS_API_KEY":
            return []  # Skip if no API key
        
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": api_key}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    return [f"{sub}.{domain}" for sub in data.get('subdomains', [])]
    except Exception as e:
        logger.warning(f"SecurityTrails API error: {e}")
    return []

async def find_subdoms_virustotal(domain: str) -> List[str]:
    """Use VirusTotal API (free tier)"""
    try:
        # Note: You'll need to get a free API key from virustotal.com
        api_key = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with actual API key
        if api_key == "YOUR_VIRUSTOTAL_API_KEY":
            return []  # Skip if no API key
        
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {"apikey": api_key, "domain": domain}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('subdomains', [])
    except Exception as e:
        logger.warning(f"VirusTotal API error: {e}")
    return []

def generate_common_subdomains(domain: str) -> List[str]:
    """Generate common subdomain combinations"""
    subdomains = []
    for sub in COMMON_SUBDOMAINS:
        subdomains.append(f"{sub}.{domain}")
    return subdomains

def is_valid_domain(domain: str) -> bool:
    """
    Validate domain format with proper regex
    Fixed: Hyphen needs to be at the end or escaped in character class
    """
    # Correct regex - hyphen at the end of character class or escaped
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

@router.post("/subdomain/find", response_model=SubdomainResponse)
async def find_subdomains(request: SubdomainRequest):
    """
    Find subdomains for a given domain using multiple techniques
    """
    try:
        domain = request.domain.lower().strip()
        
        # Validate domain format using fixed function
        if not is_valid_domain(domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
        
        logger.info(f"Starting subdomain discovery for: {domain}")
        
        all_subdomains = set()
        scan_methods = []
        
        # Method 1: Common subdomains
        common_subs = generate_common_subdomains(domain)
        all_subdomains.update(common_subs)
        scan_methods.append("common_subdomains")
        
        # Method 2: Certificate Transparency logs (crt.sh)
        crt_subs = await find_subdoms_crt_sh(domain)
        all_subdomains.update(crt_subs)
        scan_methods.append("certificate_transparency")
        
        # Method 3: SecurityTrails API (if API key available)
        securitytrails_subs = await find_subdoms_securitytrails(domain)
        if securitytrails_subs:
            all_subdomains.update(securitytrails_subs)
            scan_methods.append("securitytrails_api")
        
        # Method 4: VirusTotal API (if API key available)
        virustotal_subs = await find_subdoms_virustotal(domain)
        if virustotal_subs:
            all_subdomains.update(virustotal_subs)
            scan_methods.append("virustotal_api")
        
        # Remove duplicates and sort
        unique_subdomains = sorted(list(all_subdomains))
        
        # Check which subdomains are active
        active_subdomains = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for subdomain in unique_subdomains:
                tasks.append(check_subdomain_exists(session, subdomain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, SubdomainResult) and result.status != "inactive":
                    active_subdomains.append(result)
        
        logger.info(f"Found {len(active_subdomains)} active subdomains for {domain}")
        
        return SubdomainResponse(
            domain=domain,
            subdomains=active_subdomains,
            total_found=len(active_subdomains),
            scan_methods=scan_methods
        )
        
    except Exception as e:
        logger.error(f"Subdomain discovery error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Subdomain discovery failed: {str(e)}")

@router.get("/subdomain/health")
async def subdomain_health():
    """Health check for subdomain finder service"""
    return {
        "status": "ok",
        "service": "subdomain_finder",
        "methods_available": [
            "common_subdomains",
            "certificate_transparency", 
            "securitytrails_api",
            "virustotal_api"
        ],
        "description": "Subdomain discovery service using multiple reconnaissance techniques"
    }

@router.get("/subdomain/stats")
async def subdomain_stats():
    """Get statistics about the subdomain finder service"""
    return {
        "service": "subdomain_finder",
        "total_methods": 4,
        "free_methods": 2,
        "premium_methods": 2,
        "status": "operational"
    }

@router.post("/subdomain/validate")
async def validate_domain(request: SubdomainRequest):
    """Validate if a domain is properly formatted and potentially reachable"""
    try:
        domain = request.domain.lower().strip()
        
        # Validate domain format using fixed function
        if not is_valid_domain(domain):
            return {
                "valid": False,
                "domain": domain,
                "error": "Invalid domain format"
            }
        
        # Check if domain has DNS records
        try:
            dns.resolver.resolve(domain, 'A')
            dns_valid = True
        except:
            dns_valid = False
        
        return {
            "valid": True,
            "domain": domain,
            "dns_records": dns_valid,
            "message": "Domain is properly formatted"
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Domain validation failed: {str(e)}")