import os
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS

class ThreatAnalyzer:
    def __init__(self, index_path="botsv3_faiss_index"):
        self.embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
        self.vector_store = FAISS.load_local(index_path, self.embeddings, allow_dangerous_deserialization=True)
    
    def analyze(self, log_text):
        matches = self.vector_store.similarity_search(log_text, k=1)
        if not matches:
            return {"classification": "benign", "severity": 10, "confidence": 50, "reason": "No matches", "suggested_action": "Monitor"}
        
        best = matches[0].page_content
        
        if "<--TYPE--> malicious" in best or "malicious" in best.lower():
            return {"classification": "malicious", "severity": 90, "confidence": 85, "reason": f"Threat: {best[:100]}", "suggested_action": "Investigate immediately"}
        elif "suspicious" in best.lower():
            return {"classification": "suspicious", "severity": 60, "confidence": 70, "reason": f"Suspicious: {best[:100]}", "suggested_action": "Review logs"}
        else:
            return {"classification": "benign", "severity": 10, "confidence": 80, "reason": "No threats", "suggested_action": "Continue monitoring"}
