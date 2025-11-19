import os
from pathlib import Path
from dotenv import load_dotenv

def load_environment():
    # project root = parent of scripts/
    project_root = Path(__file__).resolve().parent.parent
    env_path = project_root / ".env"

    print(f"[ENV] Loading .env from: {env_path}")

    if not env_path.exists():
        raise RuntimeError(f"[ENV] .env not found at {env_path}")

    load_dotenv(env_path)

    # debug info
    print(f"[ENV] PINECONE_API_KEY loaded? {'YES' if os.getenv('PINECONE_API_KEY') else 'NO'}")
    print(f"[ENV] PINECONE_INDEX_NAME loaded? {os.getenv('PINECONE_INDEX_NAME')}")
    print(f"[ENV] EVIDENCE_BUCKET loaded? {os.getenv('FAFO_EVIDENCE_BUCKET')}")
