import os
from dotenv import load_dotenv

from SplunkConnector import SplunkConnector
from ThreatAnalyzer import ThreatAnalyzer
from MessageSender import MessageSender

load_dotenv()

def build_splunk_url(host, port):
    return f"{host}:{port}" if host.startswith("http") else f"https://{host}:{port}"

def main():
    try:
        host = os.getenv("SPLUNK_HOST", "localhost")
        port = os.getenv("SPLUNK_PORT", "8089")
        base_url = build_splunk_url(host, port)
        splunk = SplunkConnector(
            base_url=base_url,
            username=os.getenv("SPLUNK_USERNAME", "admin"),
            password=os.getenv("SPLUNK_PASSWORD", "")
        )
        analyzer = ThreatAnalyzer(
            groq_api_key=os.getenv("GROQ_API_KEY", "")
        )

        sender = MessageSender.from_env(
            splunk=splunk,
            analyzer=analyzer,
            index="*",
            interval=30,
            severity_threshold=10
        )
        sender.start()

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except Exception:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()