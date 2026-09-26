import re
import ipaddress
import os
from typing import Dict, Any, Literal
from state.schema import ThreatState

def validate_and_classify(input_data: str) -> str:
    """
    Evaluates the input using a rule-based parser to determine the required 
    type of cybersecurity analysis.
    """
    # 1. IP Range Classification
    # Uses the Python ipaddress module to verify syntactic correctness.
    try:
        ipaddress.ip_network(input_data.strip(), strict=False)
        return "ip"
    except ValueError:
        pass

    # 2. Log File Classification
    # Checks for completeness and proper formatting by verifying supported file extensions.
    supported_log_extensions = ['.log', '.txt', '.json', '.csv']
    _, ext = os.path.splitext(input_data.strip())
    if ext.lower() in supported_log_extensions:
        return "log"

    # 3. Email Classification
    # Uses regular expressions (regex) to verify the presence of necessary metadata fields 
    # and structural validity (e.g., standard email headers).
    email_indicators = [r"^From:\s", r"^To:\s", r"^Subject:\s", r"^Return-Path:\s"]
    if any(re.search(pattern, input_data, re.IGNORECASE | re.MULTILINE) for pattern in email_indicators):
        return "email"

    return "unknown"

def task_dispatcher_node(state: ThreatState) -> Dict[str, Any]:
    """
    The main LangGraph node for the dispatcher. It performs input validation 
    to prevent malformed or insufficient data from propagating through the analytical layers[cite: 1].
    """
    raw_input = state.get("current_input", "")
    
    if not raw_input:
        raise ValueError("Dispatcher Error: Input data is missing or incomplete.")
        
    task_type = validate_and_classify(raw_input)
    
    if task_type == "unknown":
        raise ValueError("Dispatcher Error: Unrecognized format. Input must be a valid IP/CIDR, a log file path, or raw email text.")
        
    # Updates the LangGraph state with the classified task type
    return {"current_task_type": task_type}

def route_task(state: ThreatState) -> Literal["email_verification_agent", "log_analyzer_agent", "ip_range_analyzer_agent"]:
    """
    A LangGraph conditional edge function that securely routes the task to the 
    corresponding domain agent based on the dispatcher's classification[cite: 1].
    """
    task_type = state.get("current_task_type")
    
    if task_type == "email":
        return "email_verification_agent"
    elif task_type == "log":
        return "log_analyzer_agent"
    else:
        return "ip_range_analyzer_agent"