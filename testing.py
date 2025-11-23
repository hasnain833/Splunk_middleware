import os
import json
import requests
from urllib.parse import urlparse
import argparse

# If your classes are in separate modules, uncomment and adjust imports:
# from SplunkConnector import SplunkConnector
# from LogPreprocessor import LogPreprocessor
# from RAGThreatAnalyzer import RAGThreatAnalyzer
# from AlertManager import AlertManager

from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS

from AlertManager import AlertManager
from LogPreprocessor import LogPreprocessor
from RAGThreatAnalyzer import RAGThreatAnalyzer
from SplunkConnector import SplunkConnector

# -----------------------------
# 1. CONFIGURATION
# -----------------------------

# Splunk
SPLUNK_BASE_URL = "https://localhost:8089"   # change if remote
SPLUNK_USERNAME = "Idrees"
SPLUNK_PASSWORD = "viper@7613"
SPLUNK_INDEX   = "botsv3"                    # or whatever index you want to test

# Groq
# Load Groq API key from environment. Do NOT hardcode secrets in source.
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

# FAISS
FAISS_INDEX_PATH = "botsv3_faiss_index"
EMBED_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# Alerting (optional – set to False to skip sending WhatsApp)
ENABLE_WHATSAPP_ALERTS = os.environ.get("ENABLE_WHATSAPP_ALERTS", "False").lower() in ("1", "true", "yes")
# Twilio credentials should be provided via environment variables for security.
TWILIO_SID        = os.environ.get("TWILIO_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
# WhatsApp numbers (use E.164). The code will normalize to the required `whatsapp:` prefix.
WHATSAPP_FROM     = os.environ.get("WHATSAPP_FROM", "+14155238886")   # Twilio sandbox number (placeholder)
WHATSAPP_TO       = os.environ.get("WHATSAPP_TO", "+923487613792")  # admin number (placeholder)

# Severity threshold for alerting
SEVERITY_THRESHOLD = 70

# -----------------------------
# 2. INSTANTIATE COMPONENTS
# -----------------------------

# 2.1 Splunk connector
splunk_connector = SplunkConnector(
    base_url=SPLUNK_BASE_URL,
    username=SPLUNK_USERNAME,
    password=SPLUNK_PASSWORD
)

# Basic diagnostic: detect common UI URL mistakes that return HTML instead of API JSON
if isinstance(SPLUNK_BASE_URL, str):
    lower = SPLUNK_BASE_URL.lower()
    if "/app/" in lower or "/en-" in lower or ":8000" in lower or "display.page" in lower:
        print("Warning: SPLUNK_BASE_URL looks like a Splunk web/UI URL. Use the Splunk REST API base (e.g. https://<host>:8089)")
        # Attempt a best-effort conversion: try management port 8089 on the same host
        try:
            parsed = urlparse(SPLUNK_BASE_URL)
            host = parsed.hostname
            scheme = parsed.scheme or "https"
            if host:
                candidate = f"{scheme}://{host}:8089"
                print(f"Trying Splunk API candidate base URL: {candidate}")
                try:
                    resp = requests.get(f"{candidate}/services/server/info", auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD), verify=False, timeout=5)
                    if resp.status_code == 200:
                        print("Detected Splunk API on candidate base URL; switching to it for this run.")
                        splunk_connector.base_url = candidate
                    else:
                        print("Candidate base URL did not respond with 200; not switching.")
                except Exception as e:
                    print("Candidate check failed:", e)
        except Exception:
            pass

# 2.2 Log preprocessor
log_preprocessor = LogPreprocessor()

# 2.3 Load FAISS + embeddings
print("Loading FAISS index...")
try:
    embedding = HuggingFaceEmbeddings(model_name=EMBED_MODEL_NAME)
    faiss_store = FAISS.load_local(
        FAISS_INDEX_PATH,
        embedding,
        allow_dangerous_deserialization=True
    )
    print("FAISS index loaded.")
except Exception as e:
    print("Warning: failed to load FAISS embeddings/index — falling back to dummy store.")
    print("Error:", e)

    class _DummyDoc:
        def __init__(self, content):
            self.page_content = content

    class _DummyFAISS:
        def similarity_search(self, query, k=6):
            # Return no context so downstream analysis (if any) still runs safely
            return []

    faiss_store = _DummyFAISS()

# 2.4 RAG + LLM analyzer
os.environ["GROQ_API_KEY"] = GROQ_API_KEY
try:
    rag_analyzer = RAGThreatAnalyzer(
        faiss_store=faiss_store,
        groq_api_key=GROQ_API_KEY,
        model="llama-3.1-8b-instant"
    )
except Exception as e:
    print("Warning: failed to initialize RAGThreatAnalyzer — using dummy analyzer.")
    print("Error:", e)

    class _DummyRAG:
        def __init__(self, *args, **kwargs):
            pass

        def analyze(self, log_text, k=6):
            # Return a benign JSON string so parse_json can decode it
            return json.dumps({
                "classification": "benign",
                "severity": 0,
                "confidence": 100,
                "reason": "dry-run: analyzer unavailable",
                "suggested_action": "none"
            })

        def parse_json(self, text):
            try:
                return json.loads(text)
            except:
                return None

    rag_analyzer = _DummyRAG()

# 2.5 Alert manager (optional)
alert_manager = None
if ENABLE_WHATSAPP_ALERTS:
    def _normalize_wa(num):
        if not num:
            return num
        if str(num).startswith("whatsapp:"):
            return str(num)
        return f"whatsapp:{num}"

    alert_manager = AlertManager(
        sid=TWILIO_SID,
        auth_token=TWILIO_AUTH_TOKEN,
        wa_from=_normalize_wa(WHATSAPP_FROM),
        wa_to=_normalize_wa(WHATSAPP_TO)
    )

# -----------------------------
# 3. TEST FUNCTION
# -----------------------------

def test_splunk_logs(batch_minutes=5, limit=10):
    """
    Fetch a small batch of real logs from Splunk, run RAG+LLM analysis,
    print results, and optionally send WhatsApp alerts.
    """
    print(f"\n🔍 Fetching latest logs from Splunk: index={SPLUNK_INDEX}, last {batch_minutes} minutes...")
    events = splunk_connector.fetch_latest_logs(
        index=SPLUNK_INDEX,
        minutes=batch_minutes,
        limit=limit
    )

    if not events:
        print("No events returned from Splunk. Try increasing time window or checking your index name.")
        return

    print(f"Fetched {len(events)} events.\n")

    for i, event in enumerate(events, start=1):
        print("=" * 80)
        print(f"🧾 Event {i}/{len(events)}")

        # 1) Convert event to text
        log_text = log_preprocessor.event_to_text(event)
        print("LOG TEXT SAMPLE:")
        print(log_text[:300], "...\n")

        # 2) Analyze with RAG + LLM
        result_json_text = rag_analyzer.analyze(log_text)
        result = rag_analyzer.parse_json(result_json_text)

        if not result:
            print("⚠️ Could not parse JSON from LLM response:")
            print(result_json_text)
            continue

        # 3) Print analysis
        print("🔎 AI THREAT ANALYSIS (JSON):")
        print(json.dumps(result, indent=2))

        # 4) Optional WhatsApp alert if malicious/high severity
        if (
            result.get("classification") != "benign"
            and result.get("severity", 0) >= SEVERITY_THRESHOLD
        ):
            print("🚨 This event exceeds severity threshold – would trigger alert.")
            if ENABLE_WHATSAPP_ALERTS and alert_manager is not None:
                msg = f"""
🚨 SECURITY ALERT (TEST MODE)
Classification: {result['classification']}
Severity: {result['severity']}
Confidence: {result['confidence']}
Reason: {result['reason']}
Action: {result['suggested_action']}

Event:
{log_text[:900]}
"""
                alert_manager.send_alert(msg)
        else:
            print("✅ Event considered benign or low severity (no alert).")

    print("\n✅ Test run completed.")


# -----------------------------
# 4. RUN TEST
# -----------------------------
def test_fetch_all_time_head(index=SPLUNK_INDEX, head=50):
    """
    Fetch `head` events from `index` for all time and print a short sample.
    """
    print(f"\n🔍 Fetching all-time logs from Splunk: index={index}, head={head}...")
    events = splunk_connector.fetch_all_time_head(index=index, head=head)

    if not events:
        print("No events returned from Splunk. Check SPLUNK_BASE_URL, credentials, and API access.")
        return

    print(f"Fetched {len(events)} events. Showing a compact sample for each event:\n")
    for i, event in enumerate(events, start=1):
        print("=" * 80)
        print(f"Event {i}/{len(events)}")
        try:
            # Most Splunk event dicts contain a `_raw` or `raw` field; fall back to full dict print
            raw = event.get("_raw") or event.get("raw") or json.dumps(event)
        except Exception:
            raw = str(event)
        print(raw[:1000])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run tests for Splunk_middleware")
    parser.add_argument("--send-test-alert", action="store_true", help="Send a single WhatsApp test alert and exit")
    parser.add_argument("--test-message", type=str, default=None, help="Custom test message to send with --send-test-alert")
    parser.add_argument("--head", type=int, default=50, help="Number of events to fetch when running the default test")
    args = parser.parse_args()

    if args.send_test_alert:
        # Use environment variables first, fall back to values in file
        tw_sid = os.environ.get("TWILIO_SID", TWILIO_SID)
        tw_token = os.environ.get("TWILIO_AUTH_TOKEN", TWILIO_AUTH_TOKEN)
        wa_from = os.environ.get("WHATSAPP_FROM", WHATSAPP_FROM)
        wa_to = os.environ.get("WHATSAPP_TO", WHATSAPP_TO)

        if not tw_sid or tw_sid.startswith("your_") or not tw_token or tw_token.startswith("your_"):
            print("Twilio credentials not configured. Set TWILIO_SID and TWILIO_AUTH_TOKEN environment variables or update testing.py.")
        else:
            alert_manager = AlertManager(sid=tw_sid, auth_token=tw_token, wa_from=wa_from, wa_to=wa_to)
            msg = args.test_message or f"Test WhatsApp alert from Splunk_middleware to {wa_to}"
            ok = alert_manager.send_alert(msg)
            if ok:
                print("Test alert sent successfully.")
            else:
                print("Test alert failed. See error above for details.")
        exit(0)

    # Default: fetch all-time head events from index
    test_fetch_all_time_head(index=SPLUNK_INDEX, head=args.head)
