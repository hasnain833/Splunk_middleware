import os
import json
from typing import Dict, Optional
from langchain_groq import ChatGroq
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.messages import HumanMessage

class ThreatAnalyzer:
    def __init__(self, index_path: str = "botsv3_faiss_index", groq_api_key: Optional[str] = None):
        """Initialize RAG-based threat analyzer with existing FAISS index."""
        self.index_path = index_path
        self.api_key = groq_api_key or os.getenv("GROQ_API_KEY")

        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )
        self.llm = ChatGroq(
            model="llama-3.3-70b-versatile",
            temperature=0,
            groq_api_key=self.api_key
        )
        self.vector_store = self._load_vector_store()
        self.prompt_template = """You are a cybersecurity threat analyst. Analyze the following security log event and determine if it represents a threat.
        Threat Intelligence Context:
        {context}
        Security Log Event:
        {question}
        Return ONLY a valid JSON object with this exact structure:
        {{
          "classification": "malicious|suspicious|benign",
          "severity": 0-100,
          "confidence": 0-100,
          "reason": "detailed explanation",
          "suggested_action": "specific action"
        }}"""
    
    def _load_vector_store(self) -> FAISS:
        """Load existing FAISS vector store."""
        index_file = os.path.join(self.index_path, "index.faiss")
        pkl_file = os.path.join(self.index_path, "index.pkl")
        
        if not (os.path.exists(index_file) and os.path.exists(pkl_file)):
            raise FileNotFoundError(
                f"FAISS index not found at {self.index_path}. "
                f"Expected files: index.faiss and index.pkl"
            )
        
        try:
            return FAISS.load_local(
                self.index_path,
                self.embeddings,
                allow_dangerous_deserialization=True
            )
        except Exception as e:
            raise RuntimeError(f"Failed to load FAISS index: {e}")
    
    def analyze(self, log_text: str) -> Dict:
        """Analyze security log using RAG and return threat classification."""
        try:
            retrieved_docs = self.vector_store.similarity_search(log_text, k=5)
            context = "\n\n".join([doc.page_content for doc in retrieved_docs])
            formatted_prompt = self.prompt_template.format(
                context=context,
                question=log_text
            )
            response = self.llm.invoke([HumanMessage(content=formatted_prompt)])
            answer = response.content if hasattr(response, 'content') else str(response)
            
            # Parse JSON response
            try:
                result = json.loads(answer.strip())
                result["raw_analysis"] = answer
                return result
            except json.JSONDecodeError:
                # Fallback if LLM doesn't return valid JSON
                return {
                    "classification": "benign",
                    "severity": 50,
                    "confidence": 50,
                    "reason": "Failed to parse LLM response",
                    "suggested_action": "Review log manually",
                    "raw_analysis": answer
                }
        except Exception as e:
            print(f"Error in threat analysis: {e}")
            return {
                "classification": "benign",
                "severity": 10,
                "confidence": 50,
                "reason": f"Analysis error: {str(e)}",
                "suggested_action": "Review log manually",
                "raw_analysis": None
            }
