import json
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END

# Import the shared state schema
from state.schema import ThreatState

# Import the specialized agent nodes
from agents.dispatcher import task_dispatcher_node, route_task
from agents.email_agent import email_verification_node
from agents.log_agent import log_analyzer_node
from agents.ip_agent import ip_range_analyzer_node
from agents.recommendation import recommendation_node

# Load environment variables (e.g., GROQ_API_KEY)
load_dotenv()

def build_threat_analyzer_graph():
    """
    Constructs the StateGraph for the Multi-Agent Threat Analyzer.
    """
    # Initialize the graph with the shared memory module
    workflow = StateGraph(ThreatState)

    # Add all architectural nodes
    workflow.add_node("dispatcher", task_dispatcher_node)
    workflow.add_node("email_verification_agent", email_verification_node)
    workflow.add_node("log_analyzer_agent", log_analyzer_node)
    workflow.add_node("ip_range_analyzer_agent", ip_range_analyzer_node)
    workflow.add_node("recommendation_system", recommendation_node)

    # Set the Dispatcher as the universal entry point[cite: 1]
    workflow.set_entry_point("dispatcher")

    # Add conditional routing from the dispatcher to the specific domain agents[cite: 1]
    workflow.add_conditional_edges(
        "dispatcher",
        route_task,
        {
            "email_verification_agent": "email_verification_agent",
            "log_analyzer_agent": "log_analyzer_agent",
            "ip_range_analyzer_agent": "ip_range_analyzer_agent"
        }
    )

    # Route all specialized agent outputs to the central recommendation system[cite: 1]
    workflow.add_edge("email_verification_agent", "recommendation_system")
    workflow.add_edge("log_analyzer_agent", "recommendation_system")
    workflow.add_edge("ip_range_analyzer_agent", "recommendation_system")

    # Terminate the workflow after the recommendation system generates the final report
    workflow.add_edge("recommendation_system", END)

    # Compile the graph into an executable application
    return workflow.compile()


# Initialize the architecture
app = build_threat_analyzer_graph()

if __name__ == "__main__":
    
    # Example 1: Submit an IP scanning task[cite: 1]
    print("--- Executing IP Range Analysis Task ---")
    initial_state_ip = ThreatState(
        current_input="192.168.14.0/24", 
        current_task_type=None,
        email_reports=[], 
        log_reports=[], 
        ip_reports=[],
        correlation_confidence=None,
        threat_narrative=None,
        actionable_recommendations=None
    )
    
    ip_result = app.invoke(initial_state_ip)
    print("\nFINAL THREAT NARRATIVE:\n")
    print(ip_result.get("threat_narrative"))

    # Example 2: Submit a suspicious email task using the updated state memory
    print("\n--- Executing Email Verification Task ---")
    
    # We pass the memory (ip_reports) forward to allow the recommendation 
    # system to correlate temporal events across domains[cite: 1].
    next_state_email = ThreatState(
        current_input="From: admin@paypal-secure-update.com\nSubject: URGENT: Account Locked\n\nPlease click https://paypal-secure-update.com/login to unlock your account.",
        current_task_type=None,
        email_reports=ip_result.get("email_reports", []),
        log_reports=ip_result.get("log_reports", []),
        ip_reports=ip_result.get("ip_reports", []), # Retaining previous IP scan data
        correlation_confidence=None,
        threat_narrative=None,
        actionable_recommendations=None
    )
    
    final_result = app.invoke(next_state_email)
    print("\nFINAL CORRELATED THREAT NARRATIVE:\n")
    print(final_result.get("threat_narrative"))