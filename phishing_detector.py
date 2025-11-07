import re
import socket
import requests
import tldextract
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
import logging
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class PhishingDetector:
    def __init__(self):
        self.model = None
        # Corrected feature names - match exactly with training data
        self.feature_names = [
            "having_IP_Address", "URL_Length", "Shortining_Service",  # Note: This was "Shortening_Service" in your code
            "having_At_Symbol", "double_slash_redirecting", "Prefix_Suffix",
            "having_Sub_Domain", "SSLfinal_State", "Domain_registeration_length",
            "Favicon", "port", "HTTPS_token", "Request_URL", "URL_of_Anchor",
            "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
            "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
            "age_of_domain", "DNSRecord", "web_traffic", "Page_Rank",
            "Google_Index", "Links_pointing_to_page", "Statistical_report"
        ]
        
    def load_model(self, model_path: str):
        """Load the trained model"""
        try:
            self.model = joblib.load(model_path)
            logger.info("Phishing detection model loaded successfully")
            # Print feature names to verify
            logger.info(f"Model expects features: {self.feature_names}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise

    def extract_all_30_features(self, url: str):
        features = {}

        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            ext = tldextract.extract(url)
            hostname = parsed.hostname or ''
            scheme = parsed.scheme

            response = None
            soup = None
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                response = requests.get(url, timeout=10, headers=headers, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request failed for {url}: {str(e)}")
            except Exception as e:
                logger.warning(f"HTML parsing failed for {url}: {str(e)}")

            # 1. having_IP_Address
            try:
                socket.inet_aton(hostname)
                features["having_IP_Address"] = 1
            except:
                features["having_IP_Address"] = -1

            # 2. URL_Length
            features["URL_Length"] = 1 if len(url) >= 54 else -1

            # 3. Shortining_Service (NOTE: This matches the training data)
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'shorte.st', 'go.gl', 'q.gs', 'is.gd', 'cli.gs', 'yfrog.com', 'snipurl.com', 'adf.ly', 'ow.ly', 't.co', 's.id']
            features["Shortining_Service"] = 1 if any(s in url for s in shorteners) else -1

            # 4. having_At_Symbol
            features["having_At_Symbol"] = 1 if '@' in url else -1

            # 5. double_slash_redirecting
            features["double_slash_redirecting"] = 1 if url.rfind('//') > 6 else -1

            # 6. Prefix_Suffix
            features["Prefix_Suffix"] = 1 if '-' in ext.domain else -1

            # 7. having_Sub_Domain
            dots = ext.subdomain.count('.') if ext.subdomain else 0
            features["having_Sub_Domain"] = 1 if dots > 1 else (0 if dots == 1 else -1)

            # 8. SSLfinal_State
            if scheme == 'https':
                features["SSLfinal_State"] = 1
            else:
                features["SSLfinal_State"] = -1

            # 9. Domain_registeration_length
            try:
                whois_data = whois.whois(ext.registered_domain)
                exp = whois_data.expiration_date
                crt = whois_data.creation_date
                if isinstance(exp, list): exp = exp[0]
                if isinstance(crt, list): crt = crt[0]
                if exp and crt:
                    features["Domain_registeration_length"] = -1 if (exp - crt).days > 365 else 1
                else:
                    features["Domain_registeration_length"] = 1
            except:
                features["Domain_registeration_length"] = 1

            # 10. Favicon
            try:
                if soup:
                    icon = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
                    if icon:
                        icon_href = icon.get('href', '')
                        if icon_href:
                            icon_domain = tldextract.extract(urlparse(icon_href).netloc or url).domain
                            if icon_domain != ext.domain:
                                features["Favicon"] = 1
                            else:
                                features["Favicon"] = -1
                        else:
                            features["Favicon"] = -1
                    else:
                        features["Favicon"] = -1
                else:
                    features["Favicon"] = 1
            except:
                features["Favicon"] = 1

            # 11. port
            if parsed.port and parsed.port not in [80, 443]:
                features["port"] = 1
            else:
                features["port"] = -1

            # 12. HTTPS_token
            features["HTTPS_token"] = 1 if 'https' in ext.domain else -1

            # 13. Request_URL
            try:
                if soup:
                    total_links = 0
                    suspicious_links = 0
                    for tag in soup.find_all(['img', 'script', 'link']):
                        href = tag.get('src') or tag.get('href')
                        if href and not href.startswith('#'):
                            total_links += 1
                            link_domain = tldextract.extract(urlparse(href).netloc or url).domain
                            if link_domain != ext.domain:
                                suspicious_links += 1

                    if total_links > 0:
                        features["Request_URL"] = -1 if suspicious_links > 0 else 1
                    else:
                        features["Request_URL"] = 1
                else:
                    features["Request_URL"] = -1
            except:
                features["Request_URL"] = -1

            # 14. URL_of_Anchor
            try:
                if soup:
                    total_anchors = 0
                    suspicious_anchors = 0
                    for a_tag in soup.find_all('a'):
                        href = a_tag.get('href')
                        if href and not href.startswith('#'):
                            total_anchors += 1
                            anchor_domain = tldextract.extract(urlparse(href).netloc or url).domain
                            if anchor_domain != ext.domain:
                                suspicious_anchors += 1

                    if total_anchors > 0:
                        percentage_suspicious = (suspicious_anchors / total_anchors) * 100
                        if percentage_suspicious > 67:
                            features["URL_of_Anchor"] = -1
                        elif 31 <= percentage_suspicious <= 67:
                            features["URL_of_Anchor"] = 0
                        else:
                            features["URL_of_Anchor"] = 1
                    else:
                        features["URL_of_Anchor"] = 1
                else:
                    features["URL_of_Anchor"] = -1
            except:
                features["URL_of_Anchor"] = -1

            # 15. Links_in_tags
            try:
                if soup:
                    total_links_in_tags = 0
                    suspicious_links_in_tags = 0
                    for tag in soup.find_all(['meta', 'script', 'link']):
                        href = tag.get('src') or tag.get('href')
                        if href and not href.startswith('#'):
                            total_links_in_tags += 1
                            link_domain = tldextract.extract(urlparse(href).netloc or url).domain
                            if link_domain != ext.domain:
                                suspicious_links_in_tags += 1

                    if total_links_in_tags > 0:
                        percentage_suspicious = (suspicious_links_in_tags / total_links_in_tags) * 100
                        if percentage_suspicious > 67:
                            features["Links_in_tags"] = -1
                        elif 31 <= percentage_suspicious <= 67:
                            features["Links_in_tags"] = 0
                        else:
                            features["Links_in_tags"] = 1
                    else:
                        features["Links_in_tags"] = 1
                else:
                    features["Links_in_tags"] = -1
            except:
                features["Links_in_tags"] = -1

            # 16. SFH
            try:
                if soup:
                    form_sfh = 1
                    for form in soup.find_all('form'):
                        action = form.get('action')
                        if action:
                            if action == "about:blank":
                                form_sfh = 0
                                break
                            elif tldextract.extract(urlparse(action).netloc or url).domain != ext.domain:
                                form_sfh = -1
                                break
                        else:
                            form_sfh = -1
                            break
                    features["SFH"] = form_sfh
                else:
                    features["SFH"] = -1
            except:
                features["SFH"] = -1

            # 17. Submitting_to_email
            features["Submitting_to_email"] = 1 if soup and soup.find('form', action=re.compile(r'^mailto:')) else -1

            # 18. Abnormal_URL
            features["Abnormal_URL"] = 1 if hostname in parsed.path or hostname in parsed.query else -1

            # 19. Redirect
            features["Redirect"] = 1 if response and len(response.history) >= 2 else 0

            # 20. on_mouseover
            features["on_mouseover"] = 1 if soup and re.search(r"onmouseover\\s*=\\s*['\\\"].*window\\.status.*['\\\"]", response.text, re.IGNORECASE) else -1

            # 21. RightClick
            features["RightClick"] = 1 if soup and re.search(r"event\\.button\\s*==\\s*2", response.text) else -1

            # 22. popUpWidnow
            features["popUpWidnow"] = 1 if soup and re.search(r"window\\.open", response.text) else -1

            # 23. Iframe
            features["Iframe"] = 1 if soup and soup.find('iframe') else -1

            # 24. age_of_domain
            try:
                whois_data = whois.whois(ext.registered_domain)
                creation_date = whois_data.creation_date
                if isinstance(creation_date, list): creation_date = creation_date[0]

                if creation_date:
                    age_in_days = (datetime.now() - creation_date).days
                    features["age_of_domain"] = 1 if age_in_days >= 180 else -1
                else:
                    features["age_of_domain"] = -1
            except:
                features["age_of_domain"] = -1

            # 25. DNSRecord
            try:
                socket.gethostbyname(hostname)
                features["DNSRecord"] = 1
            except socket.gaierror:
                features["DNSRecord"] = -1

            # 26-30. External API features (set to -1 as placeholders)
            features["web_traffic"] = -1
            features["Page_Rank"] = -1
            features["Google_Index"] = -1
            features["Links_pointing_to_page"] = -1
            features["Statistical_report"] = -1

        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            # Return default features in case of error
            features = {name: -1 for name in self.feature_names}

        # Ensure all features are present and in correct order
        final_features = []
        for feature_name in self.feature_names:
            final_features.append(features.get(feature_name, -1))
        
        logger.info(f"Extracted features for {url}: {dict(zip(self.feature_names, final_features))}")
        return final_features

    def predict(self, url: str):
        if not self.model:
            raise ValueError("Model not loaded. Call load_model() first.")
        
        try:
            features = self.extract_all_30_features(url)
            features_df = pd.DataFrame([features], columns=self.feature_names)
            prediction = self.model.predict(features_df)[0]
            probability = self.model.predict_proba(features_df)[0]
            
            return {
                "url": url,
                "prediction": "phishing" if prediction == -1 else "legitimate",
                "confidence": max(probability) * 100,
                "features": dict(zip(self.feature_names, features)),
                "risk_score": self.calculate_risk_score(features)
            }
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            raise

    def calculate_risk_score(self, features):
        """Calculate a risk score from 0-100 based on features"""
        risk_factors = [
            features[0] == 1,   # IP address
            features[1] == 1,   # Long URL
            features[2] == 1,   # Shortening service
            features[3] == 1,   # @ symbol
            features[5] == 1,   # Prefix/Suffix
            features[6] == 1,   # Multiple subdomains
            features[7] == -1,  # No SSL
            features[17] == 1,  # Abnormal URL
            features[22] == 1,  # Iframe
            features[23] == -1, # New domain
        ]
        risk_count = sum(risk_factors)
        return min(risk_count * 10, 100)

# Global detector instance
phishing_detector = PhishingDetector()