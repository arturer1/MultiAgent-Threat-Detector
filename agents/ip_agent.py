import os
from typing import Dict, Any
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from state.schema import ThreatState
from tools.nmap_scanner import execute_ip_extraction

def ip_range_analyzer_node(state: ThreatState) -> Dict[str, Any]:
    """
    The LangGraph node executing the predefined workflow for IP range analysis.
    """
    target_ip_or_cidr = state.get("current_input", "")
    
    # 1. Deterministic Scanning & NVD Vulnerability Extraction
    # Runs Nmap port scanning and retrieves associated CVEs from the NVD API.
    scan_results = execute_ip_extraction(target_ip_or_cidr)
    
    if "error" in scan_results:
        report = {
            "source": "ip_range_analyzer_agent",
            "raw_analysis": f"Scan failed: {scan_results['error']}",
            "structured_data": scan_results
        }
        return {"ip_reports": [report]}

    # 2. LLM Initialization
    # Connects to LLaMA 3.3-70B via Groq API for semantic risk synthesis.
    llm = ChatGroq(
        temperature=0.1,
        model_name="openai/gpt-oss-120b",
        groq_api_key=os.getenv("GROQ_API_KEY")
    )
    
    # 3. Chain-of-Thought Prompt Architecture
    # Guides the model to translate technical CVE & scan data into actionable operational reports.
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert cybersecurity IP Range Analyzer Agent.
        Your task is to analyze network scan results and mapped CVE vulnerability details for a range of IP addresses.
        
        Follow this step-by-step Chain-of-Thought reasoning process:
        1. Explain the overall risk posture in clear, natural language.
        2. Classify host risk levels based on severity and types of exposed vulnerabilities (e.g., CVSS scores, open ports).
        3. Suggest prioritization strategies for patching or isolating critical hosts/services.
        4. Tailor remediation advice to specific operational roles (Security Engineer vs. Risk Manager).
        
        Return your analysis exactly in this format:
        OVERALL RISK POSTURE: [Low, Medium, High, Critical]
        HOST RISK CLASSIFICATIONS: [Summary of host risk levels and identified vulnerabilities/CVEs]
        PATCHING & ISOLATION PRIORITIES: [Step-by-step prioritization strategies]
        REMEDIATION ADVICE:
          - For Security Engineers: [Technical action items]
          - For Risk Managers: [Strategic/compliance impact]
        """),
        ("user", """
        TARGET INPUT:
        {target}
        
        SCAN & NVD VULNERABILITY DATA:
        {scan_results}
        """)
    ])
    
    chain = prompt | llm
    response = chain.invoke({
        "target": target_ip_or_cidr,
        "scan_results": scan_results
    })
    
    # 4. Format Structured Output
    # Appends the report to 'ip_reports' in the ThreatState memory module[cite: 1].
    report = {
        "source": "ip_range_analyzer_agent",
        "raw_analysis": response.content,
        "structured_data": scan_results
    }
    
    return {"ip_reports": [report]}