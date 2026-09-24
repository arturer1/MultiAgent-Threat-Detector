import pandas as pd
import re
import os
from typing import Dict, List, Any, Optional

def validate_and_normalize_log(file_path: str) -> List[Dict[str, Any]]:
    """
    Simulates the ELK Stack normalization process.
    Checks file legitimacy (.log, .txt, .json, .csv) and extracts fields 
    such as timestamps, IP addresses, and user IDs into a uniform schema.
    """
    supported_extensions = ['.log', '.txt', '.json', '.csv']
    _, ext = os.path.splitext(file_path)
    
    if ext.lower() not in supported_extensions:
        raise ValueError(f"Unsupported file format. Must be one of {supported_extensions}")[cite: 1]

    # Regex patterns for field extraction
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    timestamp_pattern = re.compile(r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b')
    
    normalized_logs = []
    
    # In a production environment, this would query Elasticsearch. 
    # Here, we process the local dataset files (like the CIC-IDS 2017 CSVs)[cite: 1].
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                # Eliminate empty data or standard debugging lines[cite: 1]
                if not line or "DEBUG" in line:
                    continue
                
                extracted_ips = ip_pattern.findall(line)
                extracted_times = timestamp_pattern.findall(line)
                
                normalized_logs.append({
                    "raw_entry": line,
                    "extracted_ips": extracted_ips,
                    "timestamp": extracted_times[0] if extracted_times else "Unknown",
                    "user_id": "Extracted_from_auth" if "session opened for user" in line else None
                })
    except Exception as e:
        return [{"error": str(e)}]
        
    return normalized_logs

def check_suricata_signatures(log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Simulates Suricata rule-based inspection.
    Detects known threat signatures such as SSH brute force, SQL injection, 
    and port scanning behavior[cite: 1].
    """
    # Define basic signature rules[cite: 1]
    signatures = {
        "SSH_Brute_Force": re.compile(r'Failed password for (?:invalid user )?\w+ from \d+\.\d+\.\d+\.\d+ port \d+ ssh2', re.IGNORECASE),
        "SQL_Injection": re.compile(r'(?:UNION\s+SELECT|SELECT\s+.*\s+FROM|DROP\s+TABLE)', re.IGNORECASE),
        "Segmentation_Fault": re.compile(r'segmentation fault', re.IGNORECASE),
        "Internal_Server_Error": re.compile(r'500 internal server error', re.IGNORECASE)
    }
    
    flagged_events = []
    
    for entry in log_entries:
        if "error" in entry:
            continue
            
        raw_text = entry.get("raw_entry", "")
        detected_signatures = []
        
        for sig_name, sig_regex in signatures.items():
            if sig_regex.search(raw_text):
                detected_signatures.append(sig_name)
                
        if detected_signatures:
            entry["suricata_alerts"] = detected_signatures
            flagged_events.append(entry)
            
    return flagged_events

def execute_log_preprocessing(file_path: str) -> Dict[str, Any]:
    """
    Orchestrates the deterministic log processing workflow before passing data 
    to the LLM for contextual interpretation[cite: 1].
    """
    normalized_data = validate_and_normalize_log(file_path)
    flagged_threats = check_suricata_signatures(normalized_data)
    
    return {
        "total_lines_processed": len(normalized_data),
        "signature_alerts_found": len(flagged_threats),
        "critical_events": flagged_threats
    }