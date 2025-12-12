import json
import re
from groq import Groq

class ThreatAnalyzer:
    SYSTEM_PROMPT = (
        '''Analyze security logs. Reply ONLY with JSON: {
        "classification":"malicious|suspicious|benign",
        "severity":0-100,
        "confidence":0-100,
        "reason":"text",
        "suggested_action":"text"
        }'''
    )

    def __init__(self, groq_api_key, model="llama-3.1-8b-instant"):
        self.client = Groq(api_key=groq_api_key)
        self.model = model

    def analyze(self, log_text):
        """Send log text to Groq and parse the resulting JSON safely."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": f"LOG EVENT:\n{log_text}"}
                ],
                temperature=0.1
            )

            raw = response.choices[0].message.content
            return self._parse_json(raw)

        except Exception:
            return None

    def _parse_json(self, raw):
        """Attempt direct JSON parse; fall back to regex extraction."""
        try:
            return json.loads(raw)
        except Exception:
            pass

        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass

        return None
