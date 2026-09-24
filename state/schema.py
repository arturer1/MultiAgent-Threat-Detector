from typing import TypedDict, Optional, List, Dict, Any
from operator import add
from typing_extensions import Annotated

class ThreatState(TypedDict):
    # --- Current Execution Context ---
    # Captures the raw submission before validation
    current_input: str
    
    # Set by the Task Dispatcher: 'email', 'log', or 'ip'
    current_task_type: Optional[str] 
    
    # --- Agent Memory Modules ---
    # We use Annotated[List, add] to maintain a running history of all processed 
    # tasks, enabling the temporal correlation described in the paper.
    
    # Stores risk verdicts, justification trails, and metadata anomalies
    email_reports: Annotated[List[Dict[str, Any]], add]
    
    # Stores high-level tactics, sequences of suspicious entries, and confidence scores
    log_reports: Annotated[List[Dict[str, Any]], add]
    
    # Stores vulnerability metadata (CVEs), risk levels, and remediation advice
    ip_reports: Annotated[List[Dict[str, Any]], add]

    # --- Cross-Context Recommendation System ---
    # The final unified intelligence generated when correlation is found
    correlation_confidence: Optional[str]
    threat_narrative: Optional[str]
    actionable_recommendations: Optional[List[str]]