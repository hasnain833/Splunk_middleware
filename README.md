# Splunk Security Log Analyzer

A Python-based security monitoring system that fetches logs from Splunk, analyzes them using AI (LangChain + RAG), classifies them as malicious/suspicious/benign, and sends alerts via WhatsApp and Email when threats are detected.

## Features

- 🔍 **Splunk Integration**: Fetches logs from Splunk using the Splunk Python SDK
- 🤖 **AI-Powered Analysis**: Uses LangChain with RAG (Retrieval-Augmented Generation) to analyze logs
- 📊 **Threat Classification**: Classifies logs as malicious, suspicious, or benign
- 📲 **Multi-Channel Alerts**: Sends notifications via WhatsApp (Twilio) and Email (SMTP)
- 📚 **Knowledge Base**: Uses a local knowledge base for context-aware threat detection

## Requirements

- Python 3.9 or higher
- Virtual environment (recommended)
- Access to a Splunk instance
- OpenAI API key
- Twilio account (for WhatsApp notifications)
- SMTP email account (for email notifications)

## Setup

### 1. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env` and provide:
- Splunk connection details (host, port, username, password)
- Splunk search query (default: `search index=main | head 20`)
- OpenAI API key and model name
- Twilio credentials (for WhatsApp)
- SMTP credentials (for email)

### 4. Prepare Knowledge Base

Ensure the `knowledge_base/` directory contains security knowledge files (`.txt` or `.md`). Sample files are included, but you can add your own threat intelligence, MITRE ATT&CK patterns, etc.

### 5. Run the Application

```bash
python main.py
```

## Configuration

### Splunk Search Query

Edit `SPLUNK_SEARCH_QUERY` in `.env` to customize which logs are fetched. Examples:

- `search index=main earliest=-5m latest=now | head 20` - Last 5 minutes
- `search index=security sourcetype=access_combined | head 50` - Security index
- `search index=main "failed login" | head 20` - Failed login attempts

### Log Fetch Interval

Adjust `LOG_FETCH_INTERVAL_SEC` in `.env` to change how often logs are fetched (default: 300 seconds = 5 minutes).

### Disabling Notifications

If you don't want to use WhatsApp or Email notifications:

- **Disable WhatsApp**: Leave `TWILIO_ACCOUNT_SID` empty or set it to an empty string
- **Disable Email**: Leave `SMTP_HOST` empty or set it to an empty string

The application will gracefully skip unavailable notification channels.

## Project Structure

```
.
├── requirements.txt          # Python dependencies
├── README.md                # This file
├── .env.example             # Environment variable template
├── config.py                # Configuration loader
├── splunk_client.py         # Splunk integration
├── rag_setup.py             # RAG pipeline setup
├── analyzer.py              # LLM analysis logic
├── notifier.py              # WhatsApp and Email notifications
├── main.py                  # Main orchestration
└── knowledge_base/          # Security knowledge base
    └── *.md, *.txt          # Knowledge files
```

## How It Works

1. **Log Fetching**: Connects to Splunk and runs the configured search query
2. **RAG Setup**: Loads security knowledge from `knowledge_base/` into a vector store (Chroma)
3. **Analysis**: Uses OpenAI with RAG to analyze logs and classify threats
4. **Alerting**: Sends notifications via WhatsApp and Email if malicious/suspicious activity is detected
5. **Loop**: Repeats the process at the configured interval

## Testing

Before running the full system, you can test individual components:

### Quick Component Test

Run the test script to verify all components:

```bash
python test_components.py
```

This will test:
1. ✅ **Imports** - Verify all Python packages are installed
2. ✅ **Configuration** - Check .env file is set up correctly
3. ✅ **RAG Setup** - Test knowledge base loading and vector store creation
4. ✅ **Analyzer** - Test AI analysis with sample logs (requires OpenAI API key)
5. ✅ **Notifications** - Verify notification functions work
6. ✅ **Splunk Connection** - Test connection to Splunk (optional)

### Manual Testing

#### Test 1: Configuration
```bash
python -c "from config import settings; print('Config loaded:', settings.openai_model_name)"
```

#### Test 2: RAG Setup
```bash
python -c "from rag_setup import load_knowledge_base_documents; docs = load_knowledge_base_documents(); print(f'Loaded {len(docs)} documents')"
```

#### Test 3: Analyzer (with sample logs)
```python
from analyzer import analyze_logs

sample = """--- Log Entry 1 ---
event_type=authentication
status=failed
attempt_count=15
"""

result = analyze_logs(sample)
print(result)
```

#### Test 4: Run Full System
```bash
python main.py
```

## Troubleshooting

- **Splunk Connection Errors**: Verify Splunk is running and credentials are correct
- **OpenAI API Errors**: Check your API key and ensure you have credits
- **Twilio Errors**: Verify Twilio credentials and WhatsApp number format
- **Email Errors**: For Gmail, use an app-specific password, not your regular password
- **Import Errors**: Run `pip install -r requirements.txt` to install dependencies
- **Test Failures**: Check that .env file exists and has correct values

## License

This project is for educational purposes.

