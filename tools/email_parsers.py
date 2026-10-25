import re
import tldextract
import dns.resolver
from textblob import TextBlob
from typing import Dict, List, Any

def extract_urls(text: str) -> List[str]:
    """
    Uses Regular Expressions to identify and extract URLs from the email body.
    """
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    return url_pattern.findall(text)

def analyze_domain(url: str) -> Dict[str, Any]:
    """
    Decomposes the URL using tldextract and validates the domain using dns.resolver.
    Uses strict 1-second resolver timeout to avoid 10-second stalls on synthetic/dead domains.
    """
    extracted = tldextract.extract(url)
    base_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    
    domain_info = {
        "original_url": url,
        "base_domain": base_domain,
        "subdomain": extracted.subdomain,
        "dns_valid": False
    }
    
    if base_domain:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 1.0
        try:
            resolver.resolve(base_domain, 'A')
            domain_info["dns_valid"] = True
        except Exception:
            domain_info["dns_valid"] = False
            
    return domain_info

def analyze_sentiment(text: str) -> Dict[str, float]:
    """
    Performs sentiment analysis on the email content using TextBlob.
    """
    blob = TextBlob(text)
    return {
        "polarity": blob.sentiment.polarity,
        "subjectivity": blob.sentiment.subjectivity
    }

def execute_email_preprocessing(email_body: str) -> Dict[str, Any]:
    """
    Orchestrates the deterministic workflow for the Email Verification Agent.
    """
    urls = extract_urls(email_body)
    domain_analysis = [analyze_domain(url) for url in urls]
    sentiment = analyze_sentiment(email_body)
    
    return {
        "extracted_urls_count": len(urls),
        "domain_analysis": domain_analysis,
        "content_sentiment": sentiment
    }
