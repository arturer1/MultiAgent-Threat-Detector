import os
from typing import Dict, Any
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings
from state.schema import ThreatState
from tools.email_parsers import execute_email_preprocessing

def retrieve_similar_emails(query: str, k: int = 3) -> str:
    """
    Performs a vector similarity search using FAISS against the pre-indexed 
    SpamAssassin and synthetic phishing datasets.
    """
    index_path = "faiss_index/"
    
    # In a fully running environment, this loads the local FAISS index.
    # For now, we simulate the retrieval if the index directory is missing.
    if not os.path.exists(index_path):
        return "No similar historical emails found in the local database."
        
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    vector_store = FAISS.load_local(index_path, embeddings, allow_dangerous_deserialization=True)
    
    docs = vector_store.similarity_search(query, k=k)
    return "\n\n".join([f"Historical Match {i+1}: {doc.page_content}" for i, doc in enumerate(docs)])

def email_verification_node(state: ThreatState) -> Dict[str, Any]:
    """
    The LangGraph node executing the predefined workflow for email analysis[cite: 1].
    """
    raw_email = state.get("current_input", "")
    
    # 1. Deterministic Pre-processing
    # Applies RegEx, tldextract, DNS checks, and TextBlob sentiment analysis[cite: 1].
    technical_indicators = execute_email_preprocessing(raw_email)
    
    # 2. FAISS Vector Search (RAG)
    # Retrieves relevant contextual excerpts from similar phishing samples[cite: 1].
    historical_context = retrieve_similar_emails(raw_email)
    
    # 3. LLM Initialization
    # Uses LLaMA 3.3-70B via the Groq API for ultra-fast semantic reasoning[cite: 1].
    llm = ChatGroq(
        temperature=0.1,
        model_name="openai/gpt-oss-120b",
        groq_api_key=os.getenv("GROQ_API_KEY")
    )
    
    # 4. Chain-of-Thought Prompt Architecture[cite: 1]
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
    # The report provides a clear risk verdict and justification trail[cite: 1].
    report = {
        "source": "email_verification_agent",
        "raw_analysis": response.content,
        "technical_metadata": technical_indicators
    }
    
    # Appends to the 'email_reports' list in the ThreatState[cite: 1].
    return {"email_reports": [report]}