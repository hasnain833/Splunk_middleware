"""
Script to build FAISS index from threat intelligence data
Similar to classmate's approach - reads data.txt and creates vector store
"""

from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS

# Initialize embeddings
print("Loading embeddings model...")
embedder = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# Read threat intelligence data
print("Reading threat intelligence data from data.txt...")
texts = []

with open("data.txt", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:  # Skip empty lines
            texts.append(line)

print(f"Loaded {len(texts)} threat intelligence entries")

# Count malicious vs safe
malicious_count = sum(1 for text in texts if "<--TYPE--> malicious" in text)
safe_count = sum(1 for text in texts if "<--TYPE--> safe" in text)

print(f"  - Malicious entries: {malicious_count}")
print(f"  - Safe entries: {safe_count}")

# Build FAISS index
print("\nBuilding FAISS vector store...")
vectorstore = FAISS.from_texts(texts, embedder)

# Save the index
output_dir = "rag_db"
print(f"\nSaving FAISS index to '{output_dir}'...")
vectorstore.save_local(output_dir)

print("FAISS index built successfully!")
print(f"Saved to: {output_dir}/")
print(f"\nYou can now use this index in ThreatAnalyzer by setting index_path='{output_dir}'")
