import re
import tldextract
import dns.resolver
from textblob import TextBlob
from typing import Dict, List, Any

def extract_urls(text: str) -> List[str]:
    """
    Uses Regular Expressions to identify and extract URLs from the email body.
    This fulfills the requirement to spot suspicious entities and links.
    """
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    return url_pattern.findall(text)

def analyze_domain(url: str) -> Dict[str, Any]:
    """
    Decomposes the URL using tldextract and validates the domain using dns.resolver.
    """
    extracted = tldextract.extract(url)
    # Reconstruct the base domain (e.g., 'sub.malicious.com' -> 'malicious.com')
    base_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    
    domain_info = {
        "original_url": url,
        "base_domain": base_domain,
        "subdomain": extracted.subdomain,
        "dns_valid": False
    }
    
    # Perform DNS lookup for domain validation[cite: 1]
    if base_domain:
        try:
            # Check for standard A records (IPv4 addresses)
            dns.resolver.resolve(base_domain, 'A')
            domain_info["dns_valid"] = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            domain_info["dns_valid"] = False
            
    return domain_info

def analyze_sentiment(text: str) -> Dict[str, float]:
    """
    Performs sentiment analysis on the email content using TextBlob[cite: 1].
    This helps the LLM detect psychological manipulation or false urgency.
    """
    blob = TextBlob(text)
    return {
        "polarity": blob.sentiment.polarity, # -1.0 (negative) to 1.0 (positive)
        "subjectivity": blob.sentiment.subjectivity # 0.0 (objective) to 1.0 (subjective)
    }

def execute_email_preprocessing(email_body: str) -> Dict[str, Any]:
    """
    Orchestrates the deterministic workflow for the Email Verification Agent 
    before passing the data to the LLM[cite: 1].
    """
    urls = extract_urls(email_body)
    domain_analysis = [analyze_domain(url) for url in urls]
    sentiment = analyze_sentiment(email_body)
    
    return {
        "extracted_urls_count": len(urls),
        "domain_analysis": domain_analysis,
        "content_sentiment": sentiment
    }