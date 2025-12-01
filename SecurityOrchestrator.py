import time

class SecurityOrchestrator:
    def __init__(self, splunk, preprocessor, analyzer, alert_manager,
                 index="*", interval=30, severity_threshold=70):
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
        # Display index(es) - handle both single and multiple indexes
        if isinstance(self.index, str) and "," in self.index:
            index_display = f"Indexes: {self.index}"
        else:
            index_display = f"Index: {self.index}"
        print(f"   {index_display}")
        print(f"   Interval: {self.interval} seconds")
        print(f"   Severity Threshold: {self.severity_threshold}")
        print(f"   Alert System: WhatsApp (via AlertManager)")
        print()
        
        first_run = True
        
        while True:
            try:
                if first_run:
                    # First run: Fetch all existing data using fetch_all_time_head method
                    index_display = self.index if isinstance(self.index, str) and "," not in self.index else f"indexes: {self.index}"
                    print(f"📥 Initial scan: Fetching all existing security logs from {index_display}...")
                    # Use the existing method that handles the query properly
                    events = self.splunk.fetch_security_logs_all_time(
                        index=self.index,
                        limit=5
                    )
                    print(f"   Retrieved {len(events)} existing events")
                    first_run = False
                else:
                    # Subsequent runs: Only fetch new data (last 1 minute)
                    index_display = self.index if isinstance(self.index, str) and "," not in self.index else f"indexes: {self.index}"
                    print(f"📥 Fetching new security logs from {index_display} (last 1 minute)...")
                    events = self.splunk.fetch_security_logs(
                        index=self.index, 
                        minutes=1, 
                        limit=5
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
                            # Extract specific event details
                            event_time = event.get('_time', 'N/A')
                            event_host = event.get('host', 'N/A')
                            event_sourcetype = event.get('sourcetype', 'N/A')
                            event_source = event.get('source', 'N/A')
                            event_src = event.get('src', event.get('source_ip', 'N/A'))
                            event_dest = event.get('dest', event.get('dest_ip', 'N/A'))
                            event_user = event.get('user', event.get('username', 'N/A'))
                            event_action = event.get('action', event.get('signature', 'N/A'))
                            event_index = event.get('index', self.index)
                            
                            # Format specific alert message
                            msg = f"""🚨 SECURITY THREAT DETECTED

⚠️ THREAT TYPE: {result['classification'].upper()}
🔴 SEVERITY: {result['severity']}/100
📊 CONFIDENCE: {result['confidence']}%

📍 EVENT LOCATION:
   • Host: {event_host}
   • Index: {event_index}
   • Source: {event_source}
   • Sourcetype: {event_sourcetype}

🌐 NETWORK DETAILS:
   • Source IP: {event_src}
   • Destination IP: {event_dest}

👤 USER CONTEXT:
   • User: {event_user}
   • Action: {event_action}

⏰ TIMESTAMP: {event_time}

🔍 THREAT ANALYSIS:
{result['reason']}

✅ RECOMMENDED ACTION:
{result['suggested_action']}

📋 RAW EVENT DATA:
{log_text[:500]}

---
Event ID: {i}/{len(events)}
Detection Time: {event_time}
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
