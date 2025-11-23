import time

class SecurityOrchestrator:
    def __init__(self, splunk, preprocessor, analyzer, alert_manager,
                 index="botsv3", interval=60, severity_threshold=70):
        self.splunk = splunk
        self.preprocessor = preprocessor
        self.analyzer = analyzer
        self.alert_manager = alert_manager
        self.index = index
        self.interval = interval
        self.severity_threshold = severity_threshold

    def start(self):
        """
        Main monitoring loop.
        """
        print("🔍 Security Monitoring Started...")
        
        while True:
            events = self.splunk.fetch_latest_logs(self.index, minutes=5, limit=200)

            for event in events:
                log_text = self.preprocessor.event_to_text(event)

                # Perform RAG LLM threat analysis
                result_json = self.analyzer.analyze(log_text)
                result = self.analyzer.parse_json(result_json)

                if not result:
                    continue

                # Check if alert should be sent
                if result["classification"] != "benign" and result["severity"] >= self.severity_threshold:
                    msg = f"""
🚨 SECURITY ALERT
Classification: {result['classification']}
Severity: {result['severity']}
Confidence: {result['confidence']}
Reason: {result['reason']}
Action: {result['suggested_action']}

Event: {log_text[:1000]}
"""
                    self.alert_manager.send_alert(msg)

            time.sleep(self.interval)
