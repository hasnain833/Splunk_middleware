import re

class ThreatAnalyzer:
    def __init__(self):
        self.malicious_patterns = [
            (r"unauthorized\s+access", 95),
            (r"privilege\s+escalation", 90),
            (r"sql\s+injection", 95),
            (r"xss\s+cross.site", 85),
            (r"malware\s+detected", 100),
            (r"ransomware", 100),
            (r"data\s+exfiltration", 90),
            (r"root\s+kit", 95),
            (r"backdoor", 90),
            (r"command\s+injection", 90),
        ]
        
        self.suspicious_patterns = [
            (r"failed\s+login", 60),
            (r"brute\s+force", 75),
            (r"port\s+scan", 55),
            (r"firewall\s+blocked", 50),
            (r"unusual\s+activity", 65),
            (r"anomalous\s+behavior", 60),
            (r"multiple\s+failed", 70),
            (r"suspicious\s+connection", 65),
            (r"unexpected\s+traffic", 55),
            (r"access\s+denied", 45),
        ]

    def analyze(self, log_text):
        log_lower = log_text.lower()
        
        for pattern, severity in self.malicious_patterns:
            if re.search(pattern, log_lower, re.IGNORECASE):
                return {
                    "classification": "malicious",
                    "severity": severity,
                    "confidence": 85,
                    "reason": f"Detected malicious pattern: {pattern}",
                    "suggested_action": "Immediately investigate and isolate affected systems"
                }
        
        for pattern, severity in self.suspicious_patterns:
            if re.search(pattern, log_lower, re.IGNORECASE):
                return {
                    "classification": "suspicious",
                    "severity": severity,
                    "confidence": 70,
                    "reason": f"Detected suspicious pattern: {pattern}",
                    "suggested_action": "Review logs and monitor for further activity"
                }
        
        return {
            "classification": "benign",
            "severity": 10,
            "confidence": 80,
            "reason": "No known threat patterns detected",
            "suggested_action": "Continue monitoring"
        }
