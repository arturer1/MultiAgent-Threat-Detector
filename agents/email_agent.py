import os
from typing import Dict, Any, Optional
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings
from state.schema import ThreatState
from tools.email_parsers import execute_email_preprocessing

# Module-level cache: Load model and index once, reuse across all invocations
_CACHED_EMBEDDINGS: Optional[HuggingFaceEmbeddings] = None
_CACHED_VECTOR_STORE: Optional[FAISS] = None

def get_vector_store() -> Optional[FAISS]:
    """
    Singleton loader for the FAISS vector store and HuggingFace embeddings
    to prevent repetitive model deserialization overhead.
    """
    global _CACHED_EMBEDDINGS, _CACHED_VECTOR_STORE
    index_path = "faiss_index/"
    
    if not os.path.exists(index_path):
        return None

    if _CACHED_VECTOR_STORE is None:
        if _CACHED_EMBEDDINGS is None:
            _CACHED_EMBEDDINGS = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        _CACHED_VECTOR_STORE = FAISS.load_local(
            index_path, 
            _CACHED_EMBEDDINGS, 
            allow_dangerous_deserialization=True
        )
    return _CACHED_VECTOR_STORE

def retrieve_similar_emails(query: str, k: int = 3) -> str:
    """
    Performs a vector similarity search using FAISS against the pre-indexed 
    SpamAssassin and synthetic phishing datasets.
    """
    vector_store = get_vector_store()
    if vector_store is None:
        return "No similar historical emails found in the local database."
        
    docs = vector_store.similarity_search(query, k=k)
    return "\n\n".join([f"Historical Match {i+1}: {doc.page_content}" for i, doc in enumerate(docs)])

def email_verification_node(state: ThreatState) -> Dict[str, Any]:
    """
    The LangGraph node executing the predefined workflow for email analysis.
    """
    raw_email = state.get("current_input", "")
    
    # 1. Deterministic Pre-processing (fast regex, DNS, sentiment)
    technical_indicators = execute_email_preprocessing(raw_email)
    
    # 2. FAISS Vector Search (RAG via cached index)
    historical_context = retrieve_similar_emails(raw_email)
    
    # 3. LLM Initialization
    llm = ChatGroq(
        temperature=0.1,
        model_name="openai/gpt-oss-20b",
        groq_api_key=os.getenv("GROQ_API_KEY")
    )
    
    # 4. Chain-of-Thought Prompt Architecture
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an expert cybersecurity Email Verification Agent. 
        Your task is to analyze the provided email and intermediate tool outputs.
        
        Follow this step-by-step Chain-of-Thought reasoning process:
        1. Analyze the structural metadata and DNS validity of extracted domains.
        2. Evaluate the sentiment (e.g., psychological manipulation, false urgency).
        3. Compare the content against the retrieved historical vector matches.
        4. Synthesize these signals into a clear risk verdict and justification trail.
        
        Return your analysis exactly in this format:
        VERDICT: [Safe, Suspicious, or Phishing]
        JUSTIFICATION: [Your step-by-step reasoning trail]
        """),
        ("user", """
        RAW EMAIL:
        {email_content}
        
        TECHNICAL INDICATORS (Deterministic Tools):
        {technical_indicators}
        
        HISTORICAL CONTEXT (FAISS Matches):
        {historical_context}
        """)
    ])
    
    chain = prompt | llm
    response = chain.invoke({
        "email_content": raw_email,
        "technical_indicators": technical_indicators,
        "historical_context": historical_context
    })
    
    # 5. Format Structured Output
    report = {
        "source": "email_verification_agent",
        "raw_analysis": response.content,
        "technical_metadata": technical_indicators
    }
    
    return {"email_reports": [report]}
