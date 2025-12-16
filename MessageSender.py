import time

class MessageSender:
    def __init__(self, splunk, analyzer, client=None, from_number=None, to_number=None):
        self.splunk = splunk
        self.analyzer = analyzer
        self.client = client
        self.from_number = from_number
        self.to_number = to_number
        self.interval = 30

    def _send_whatsapp(self, message):
        if not self.client or not self.from_number or not self.to_number:
            print("  ERROR: Twilio not configured")
            return False
        try:
            msg = self.client.messages.create(from_=self.from_number, to=self.to_number, body=message)
            print(f"  WhatsApp alert sent!")
            return True
        except Exception as e:
            print(f"  ERROR sending WhatsApp: {e}")
            return False

    def start(self):
        print("Starting security monitoring...")
        first_run = True

        while True:
            try:
                minutes = None if first_run else 5
                print(f"Fetching logs (minutes={minutes})...")
                
                events = self.splunk.fetch_security_logs(index="*", minutes=minutes, limit=5)
                print(f"Found {len(events)} events")
                
                if len(events) == 0:
                    print("  No events to analyze")
                else:
                    for i, event in enumerate(events, 1):
                        log_text = event.get("_raw", str(event))
                        result = self.analyzer.analyze(log_text)
                        
                        # Print all logs to console with consistent format
                        classification = result['classification']
                        severity = result['severity']
                        confidence = result['confidence']
                        reason = result['reason']
                        
                        print(f"  Event {i}: {classification.upper()} (severity={severity}, confidence={confidence})")
                        print(f"    Log: {log_text[:150]}...")
                        print(f"    Reason: {reason}")
                        print(f"    Action: {result['suggested_action']}")
                        
                        # Send WhatsApp ALERT ONLY for malicious/suspicious (NOT for benign)
                        if classification in ['malicious', 'suspicious']:
                            msg = f"SECURITY ALERT: {classification.upper()}\nSeverity: {severity}\nReason: {reason}\nAction: {result['suggested_action']}\nRaw: {log_text[:100]}"
                            self._send_whatsapp(msg)
                        else:
                            print(f"    Status: Normal activity - no alert sent")
                
                first_run = False
                print(f"Waiting {self.interval} seconds...\n")
                time.sleep(self.interval)
            except KeyboardInterrupt:
                print("\nMonitoring stopped.")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(self.interval)
