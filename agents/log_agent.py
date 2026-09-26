import os
from typing import Dict, Any
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from state.schema import ThreatState
from tools.log_processors import execute_log_preprocessing

def log_analyzer_node(state: ThreatState) -> Dict[str, Any]:
    """
    The LangGraph node executing the predefined workflow for log analysis.
    """
    # The dispatcher ensures current_input is a valid file path before routing here
    log_file_path = state.get("current_input", "")
    
    # 1. Deterministic Pre-processing & Normalization
    # Simulates ELK stack filtering to extract timestamps and IP addresses, 
    # and uses Suricata rules to flag known signatures.
    processed_logs = execute_log_preprocessing(log_file_path)
    
    # 2. Temporal Correlation (Memory Module)
    # Retrieves historical log behaviors to track evolving threats, such as repeated 
    # attempts by the same user to access sensitive directories across sessions[cite: 1].
    historical_logs = state.get("log_reports", [])
    recent_history = historical_logs[-3:] if historical_logs else "No previous log history recorded."

    # 3. LLM Initialization
    # Uses LLaMA 3.3-70B via the Groq API for contextual interpretation[cite: 1].
    llm = ChatGroq(
        temperature=0.1,
        model_name="openai/gpt-oss-120b",
        groq_api_key=os.getenv("GROQ_API_KEY")
    )
    
    # 4. Chain-of-Thought Prompt Architecture
    # Forces the LLM to summarize events, deduce high-level tactics, and reference 
    # exact lines of the log to preserve transparency (Explainable AI)[cite: 1].
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert cybersecurity Log Analyzer Agent.
        Your task is to interpret sequences of suspicious log entries enriched with metadata and prior alert scores.
        
        Follow this step-by-step Chain-of-Thought reasoning process:
        1. Summarize the events in coherent, human-readable language.
        2. Identify abnormal patterns or escalation attempts (e.g., successful sudo commands following failed authentications).
        3. Deduce high-level tactics, such as reconnaissance or persistence, based on time, user behavior, and command types.
        4. Compare the current events against historical behaviors to spot temporal anomalies.
        5. Provide a confidence score or risk level.
        
        You must reference the exact lines of the log in your justification to preserve analytical transparency.
        
        Return your analysis exactly in this format:
        RISK LEVEL: [Low, Medium, High, Critical]
        TACTICS DETECTED: [List of high-level tactics]
        JUSTIFICATION: [Your step-by-step explanation referencing specific log entries]
        """),
        ("user", """
        PROCESSED LOG DATA (ELK/Suricata outputs):
        {processed_logs}
        
        HISTORICAL BEHAVIOR (Memory Module):
        {historical_logs}
        """)
    ])
    
    chain = prompt | llm
    response = chain.invoke({
        "processed_logs": processed_logs,
        "historical_logs": recent_history
    })
    
    # 5. Format Structured Output
    # This dictionary feeds directly into the centralized Contextual Recommendation System[cite: 1].
    report = {
        "source": "log_analyzer_agent",
        "raw_analysis": response.content,
        "structured_data": processed_logs
    }
    
    return {"log_reports": [report]}