import time

class MessageSender:
    def __init__(self, splunk, analyzer, client=None, from_number=None, to_number=None):
        self.splunk = splunk
        self.analyzer = analyzer
        self.index = "*"
        self.interval = 30
        self.client = client
        self.from_number = from_number
        self.to_number = to_number

    def _send_whatsapp(self, message):
        if not self.client or not self.from_number or not self.to_number:
            print("  ERROR: Twilio not configured")
            return False
        try:
            msg = self.client.messages.create(
                from_=self.from_number,
                to=self.to_number,
                body=message
            )
            print(f"  WhatsApp alert sent! SID={getattr(msg, 'sid', 'N/A')}")
            return True
        except Exception as e:
            print(f"  ERROR sending WhatsApp: {e}")
            return False

    def _process_events(self, events):
        for i, event in enumerate(events, start=1):
            print(f"Analyzing event {i}/{len(events)}...")
            log_text = event.get("_raw", str(event))
            result = self.analyzer.analyze(log_text)

            if not result:
                print(f"  Event {i}: Analysis failed — skipping")
                continue

            print(f"  Event {i}: {result['classification'].upper()} (severity={result['severity']})")
            msg = f"SECURITY ALERT: {result['classification'].upper()}\nSeverity: {result['severity']}\nAnalysis: {result['reason']}\nAction: {result['suggested_action']}\nRaw: {log_text[:50]}"

            if self._send_whatsapp(msg):
                print("  Alert sent successfully!")
            else:
                print("  Alert failed.")

    def start(self):
        print("Starting security monitoring...")
        first_run = True

        while True:
            try:
                minutes = None if first_run else 1
                print(f"Fetching logs (index={self.index}, minutes={minutes})...")

                events = self.splunk.fetch_security_logs(
                    index=self.index, minutes=minutes, limit=5
                )

                print(f"Found {len(events)} events")
                if events:
                    self._process_events(events)

                first_run = False
                print(f"Waiting {self.interval} seconds...\n")

            except Exception:
                import traceback
                traceback.print_exc()

            time.sleep(self.interval)
