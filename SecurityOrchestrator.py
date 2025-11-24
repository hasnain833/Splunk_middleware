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
        Fetches security logs from Splunk, analyzes them for threats, and sends WhatsApp alerts.
        First run: Fetches all existing data. Subsequent runs: Only new data (last 5 minutes).
        """
        print("🔍 Security Monitoring Started...")
        print(f"   Index: {self.index}")
        print(f"   Interval: {self.interval} seconds")
        print(f"   Severity Threshold: {self.severity_threshold}")
        print(f"   Alert System: WhatsApp (via AlertManager)")
        print()
        
        first_run = True
        
        while True:
            try:
                if first_run:
                    # First run: Fetch all existing data using fetch_all_time_head method
                    print(f"📥 Initial scan: Fetching all existing security logs from {self.index}...")
                    # Use the existing method that handles the query properly
                    events = self.splunk.fetch_security_logs_all_time(
                        index=self.index,
                        limit=5000
                    )
                    print(f"   Retrieved {len(events)} existing events")
                    first_run = False
                else:
                    # Subsequent runs: Only fetch new data (last 5 minutes)
                    print(f"📥 Fetching new security logs from {self.index} (last 5 minutes)...")
                    events = self.splunk.fetch_security_logs(
                        index=self.index, 
                        minutes=5, 
                        limit=5000
                    )
                    print(f"   Retrieved {len(events)} new events")
                
                if not events:
                    print("   ℹ️  No events found")
                else:
                    # Analyze each event
                    alerts_sent = 0
                    for i, event in enumerate(events, 1):
                        log_text = self.preprocessor.event_to_text(event)

                        # Perform RAG LLM threat analysis
                        result_json = self.analyzer.analyze(log_text)
                        result = self.analyzer.parse_json(result_json)

                        if not result:
                            continue

                        # Check if alert should be sent
                        if result["classification"] != "benign" and result["severity"] >= self.severity_threshold:
                            # Format alert message
                            msg = f"""🚨 SECURITY ALERT

Classification: {result['classification']}
Severity: {result['severity']}/100
Confidence: {result['confidence']}%

Reason: {result['reason']}

Suggested Action: {result['suggested_action']}

Event Details:
{log_text[:800]}

---
Event {i}/{len(events)}
Time: {event.get('_time', 'N/A')}
Host: {event.get('host', 'N/A')}
Sourcetype: {event.get('sourcetype', 'N/A')}
"""
                            # Send WhatsApp alert
                            print(f"   ⚠️  Threat detected! Sending alert...")
                            success = self.alert_manager.send_alert(msg)
                            if success:
                                alerts_sent += 1
                                print(f"   ✅ Alert sent successfully via WhatsApp")
                            else:
                                print(f"   ❌ Failed to send alert")
                    
                    if alerts_sent > 0:
                        print(f"\n   📊 Summary: {alerts_sent} alert(s) sent for {len(events)} events analyzed")
                
            except Exception as e:
                print(f"❌ Error in monitoring loop: {e}")
                import traceback
                traceback.print_exc()
            
            print(f"\n⏳ Waiting {self.interval} seconds before next check...\n")
            time.sleep(self.interval)
