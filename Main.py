import os
from dotenv import load_dotenv
from splunklib import client
from twilio.rest import Client
from SplunkConnector import SplunkConnector
from ThreatAnalyzer import ThreatAnalyzer
from MessageSender import MessageSender

load_dotenv()

def main():
    service = client.connect(
        host=os.getenv("SPLUNK_HOST", "localhost"),
        port=int(os.getenv("SPLUNK_PORT", "8089")),
        username=os.getenv("SPLUNK_USERNAME", "admin"),
        password=os.getenv("SPLUNK_PASSWORD", ""),
        scheme="https"
    )
    
    splunk = SplunkConnector(service)
    analyzer = ThreatAnalyzer(index_path="rag_db")
    
    twilio_client = None
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    if sid and auth_token:
        twilio_client = Client(sid, auth_token)
    
    sender = MessageSender(
        splunk=splunk,
        analyzer=analyzer,
        client=twilio_client,
        from_number=os.getenv("TWILIO_WHATSAPP_FROM"),
        to_number=os.getenv("ALERT_WHATSAPP_TO")
    )
    sender.start()

if __name__ == "__main__":
    main()
