import json
from groq import Groq

class RAGThreatAnalyzer:
    def __init__(self, faiss_store, groq_api_key, model="llama-3.1-8b-instant"):
        self.faiss_store = faiss_store
        self.client = Groq(api_key=groq_api_key)
        self.model = model

    def analyze(self, log_text, k=6):
        """
        Full RAG pipeline:
        1. Retrieve similar logs
        2. Build prompt
        3. Query Groq Llama model
        4. Return JSON threat classification
        """
        # Retrieve similar logs
        results = self.faiss_store.similarity_search(log_text, k=k)
        context = "\n\n".join([r.page_content for r in results])

        system_prompt = """
You are a cybersecurity threat analyst. You MUST reply ONLY with valid JSON.
JSON format:
{
 "classification": "malicious"|"suspicious"|"benign",
 "severity": 0-100,
 "confidence": 0-100,
 "reason": "text",
 "suggested_action": "text"
}
"""

        user_prompt = f"""
LOG EVENT:
{log_text}

CONTEXT:
{context}
"""

        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1
        )

        return resp.choices[0].message.content

    def parse_json(self, text):
        """
        Safely parse JSON returned by LLM.
        """
        try:
            return json.loads(text)
        except:
            import re
            match = re.search(r"\{.*\}", text, re.S)
            if match:
                return json.loads(match.group(0))
            return None
