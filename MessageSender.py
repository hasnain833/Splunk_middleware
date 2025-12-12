import os
import time
from twilio.rest import Client

class MessageSender:
    def __init__(self, splunk, analyzer, sid=None, auth_token=None, from_number=None, to_number=None,
                 index="*", interval=30, severity_threshold=70):

        self.splunk = splunk
        self.analyzer = analyzer
        self.index = index
        self.interval = interval
        self.severity_threshold = severity_threshold
        self.client = Client(sid, auth_token) if sid and auth_token else None
        self.from_number = from_number
        self.to_number = to_number

    @classmethod
    def from_env(cls, splunk, analyzer, index="*", interval=30, severity_threshold=70):
        return cls(
            splunk, analyzer,
            os.getenv("TWILIO_ACCOUNT_SID"),
            os.getenv("TWILIO_AUTH_TOKEN"),
            os.getenv("TWILIO_WHATSAPP_FROM"),
            os.getenv("ALERT_WHATSAPP_TO"),
            index=index, interval=interval, severity_threshold=severity_threshold
        )

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

    def _extract_event_data(self, event):
        return event.get("_raw", str(event))

    def _format_message(self, result, log_text):
        return (
            f"SECURITY THREAT: {result['classification'].upper()}\n"
            f"Analysis: {result['reason']}\n"
            f"Action: {result['suggested_action']}\n"
            f"Raw: {log_text[:50]}"
        )

    def _process_events(self, events):
        for i, event in enumerate(events, start=1):

            print(f"Analyzing event {i}/{len(events)}...")
            log_text = self._extract_event_data(event)
            result = self.analyzer.analyze(log_text)

            if not result:
                print(f"  Event {i}: Analysis failed — skipping")
                continue

            if result.get("classification") == "benign":
                print(f"  Event {i}: Benign (severity={result['severity']}) — skipped")
                continue

            if result["severity"] < self.severity_threshold:
                print(f"  Event {i}: Low severity ({result['severity']}) — below threshold")
                continue

            print(f"  Event {i}: THREAT DETECTED! severity={result['severity']}")
            msg = self._format_message(result, log_text)

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
