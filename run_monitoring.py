"""
Main script to run the Splunk Security Monitoring System.
This integrates Splunk, RAG threat analysis, and WhatsApp alerts.
"""
import os
from dotenv import load_dotenv
from SplunkConnector import SplunkConnector
from LogPreprocessor import LogPreprocessor
from RAGThreatAnalyzer import RAGThreatAnalyzer
from AlertManager import AlertManager
from SecurityOrchestrator import SecurityOrchestrator

# Load environment variables
load_dotenv()

def load_faiss_store():
    """Load the FAISS vector store for RAG."""
    try:
        from langchain_community.vectorstores import FAISS
        from langchain_community.embeddings import HuggingFaceEmbeddings
        
        # Load embeddings
        embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )
        
        # Load FAISS index
        faiss_path = "botsv3_faiss_index"
        if os.path.exists(faiss_path):
            print(f"📚 Loading FAISS index from {faiss_path}...")
            faiss_store = FAISS.load_local(faiss_path, embeddings, allow_dangerous_deserialization=True)
            print("✅ FAISS index loaded successfully!")
            return faiss_store
        else:
            print(f"⚠️  FAISS index not found at {faiss_path}")
            print("   Creating empty FAISS store (will work but without RAG context)...")
            # Create empty FAISS store
            from langchain.schema import Document
            faiss_store = FAISS.from_documents([Document(page_content="")], embeddings)
            return faiss_store
    except Exception as e:
        print(f"⚠️  Error loading FAISS store: {e}")
        print("   Continuing without RAG context...")
        return None

def main():
    """Initialize and start the security monitoring system."""
    print("=" * 60)
    print("🚀 Splunk Security Monitoring System")
    print("=" * 60)
    print()
    
    # Get configuration from environment
    splunk_host = os.environ.get("SPLUNK_HOST", "localhost")
    splunk_port = os.environ.get("SPLUNK_PORT", "8089")
    splunk_username = os.environ.get("SPLUNK_USERNAME", "admin")
    splunk_password = os.environ.get("SPLUNK_PASSWORD", "")
    groq_api_key = os.environ.get("GROQ_API_KEY", "")
    
    # Construct Splunk URL
    if not splunk_host.startswith("http"):
        if splunk_port in ["8000", "8001"]:
            splunk_port = "8089"  # Use management port
        splunk_base_url = f"https://{splunk_host}:{splunk_port}"
    else:
        splunk_base_url = f"{splunk_host}:{splunk_port}"
    
    # Validate required configuration
    if not splunk_password:
        print("❌ Error: SPLUNK_PASSWORD not set in environment variables")
        return
    
    if not groq_api_key:
        print("❌ Error: GROQ_API_KEY not set in environment variables")
        return
    
    try:
        # Initialize components
        print("📦 Initializing components...")
        
        # 1. Splunk Connector
        print("   1. Splunk Connector...")
        splunk = SplunkConnector(
            base_url=splunk_base_url,
            username=splunk_username,
            password=splunk_password
        )
        print("      ✅ Connected to Splunk")
        
        # 2. Log Preprocessor
        print("   2. Log Preprocessor...")
        preprocessor = LogPreprocessor()
        print("      ✅ Initialized")
        
        # 3. FAISS Store for RAG
        print("   3. FAISS Vector Store (RAG)...")
        try:
            faiss_store = load_faiss_store()
            if faiss_store:
                print("      ✅ Loaded")
            else:
                print("      ⚠️  Not available (continuing without RAG)")
        except Exception as e:
            print(f"      ⚠️  Error loading FAISS: {e}")
            print("      Continuing without RAG context (AI will still work)")
            faiss_store = None
        
        # 4. RAG Threat Analyzer
        print("   4. RAG Threat Analyzer...")
        analyzer = RAGThreatAnalyzer(
            faiss_store=faiss_store,
            groq_api_key=groq_api_key,
            model="llama-3.1-8b-instant"
        )
        print("      ✅ Initialized with Groq API")
        
        # 5. Alert Manager (WhatsApp)
        print("   5. Alert Manager (WhatsApp)...")
        alert_manager = AlertManager.from_env()
        print("      ✅ Configured for WhatsApp alerts")
        
        print()
        print("=" * 60)
        print("✅ All components initialized successfully!")
        print("=" * 60)
        print()
        
        # 6. Security Orchestrator
        orchestrator = SecurityOrchestrator(
            splunk=splunk,
            preprocessor=preprocessor,
            analyzer=analyzer,
            alert_manager=alert_manager,
            index="botsv3",
            interval=60,  # Check every 60 seconds
            severity_threshold=70  # Alert if severity >= 70
        )
        
        # Start monitoring
        orchestrator.start()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Monitoring stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

