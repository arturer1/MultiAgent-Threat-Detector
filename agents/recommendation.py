import os
import re
import json
from typing import Dict, Any, List, Set
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from state.schema import ThreatState

def extract_shared_entities(reports: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Uses regular expressions to detect common entities such as IP addresses, URLs, 
    or domain names that may appear in different analysis contexts[cite: 1].
    """
    combined_text = json.dumps(reports)
    
    # Basic regex patterns for cross-context entities[cite: 1]
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    
    # Using sets to ensure unique entities, then converting back to lists for JSON serialization
    found_ips = list(set(ip_pattern.findall(combined_text)))
    found_urls = list(set(url_pattern.findall(combined_text)))
    
    return {
        "shared_ips": found_ips,
        "shared_urls": found_urls
    }

def recommendation_node(state: ThreatState) -> Dict[str, Any]:
    """
    Acts as the consolidation and correlation center of the architecture, 
    transforming agent-specific results into actionable information[cite: 1].
    """
    # 1. Normalize and Aggregate Data
    # Collects structured results from the email, log, and IP agents[cite: 1].
    all_reports = (
        state.get("email_reports", []) + 
        state.get("log_reports", []) + 
        state.get("ip_reports", [])
    )
    
    if not all_reports:
        return {"threat_narrative": "No threat data available to correlate."}

    # 2. Entity Matching
    # Searches for syntactic matches to flag correlated anomalies[cite: 1].
    shared_entities = extract_shared_entities(all_reports)

    # 3. LLM Initialization
    # Employs the LLaMA 3.3-70B model accessible via the Groq API[cite: 1].
    llm = ChatGroq(
        temperature=0.1,
        model_name="openai/gpt-oss-120b",
        groq_api_key=os.getenv("GROQ_API_KEY")
    )

    # 4. Prompt Architecture for Cross-Context Reasoning
    # Guides the LLM to structure a comprehensive report based on the correlated events[cite: 1].
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the Contextual Recommendation System. Your role is to synthesize data from multiple cybersecurity agents into a unified threat landscape view.
        
        Based on the provided agent reports and extracted shared entities, perform the following:
        1. Apply temporal correlation by examining the timing of events (e.g., identifying phishing campaigns followed by lateral movement)[cite: 1].
        2. Assign a correlation confidence level indicating the likelihood that these events are part of a unified threat scenario[cite: 1].
        3. Structure a final report avoiding overgeneralization and ensuring consistency[cite: 1].
        
        Return your analysis exactly in this format:
        CORRELATION CONFIDENCE: [Low, Medium, High, Critical]
        NARRATIVE SUMMARY: [Narrative summary of the incident][cite: 1]
        EVIDENCE TRACES: [Bullet points of evidence traces from each agent involved][cite: 1]
        ACTIONABLE RECOMMENDATIONS: [List of actionable recommendations][cite: 1]
        """),
        ("user", """
        AGENT REPORTS:
        {reports}
        
        SHARED ENTITIES IDENTIFIED ACROSS DOMAINS:
        {entities}
        """)
    ])

    chain = prompt | llm
    response = chain.invoke({
        "reports": json.dumps(all_reports, indent=2),
        "entities": json.dumps(shared_entities, indent=2)
    })

    # 5. Output Synchronization
    # Populates the unified threat intelligence into the StateGraph memory module.
    return {
        "threat_narrative": response.content
    }