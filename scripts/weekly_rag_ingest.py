import csv
import io
import os
import json
from datetime import datetime
import boto3
from pinecone import Pinecone, ServerlessSpec
# or however you already init Pinecone
from dotenv import load_dotenv

load_dotenv()

s3 = boto3.client("s3")

PINECONE_API_KEY = os.environ["PINECONE_API_KEY"]
PINECONE_INDEX_NAME = os.environ["PINECONE_INDEX_NAME"]
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "text-embedding-ada-002")  # example

pc = Pinecone(api_key=PINECONE_API_KEY)
index = pc.Index(PINECONE_INDEX_NAME)


def embed_text(text: str) -> list[float]:
    """Call your embedding model here (OpenAI, Bedrock, etc.)."""
    # Pseudocode – replace with your real client
    from openai import OpenAI
    client = OpenAI()
    resp = client.embeddings.create(
        model=EMBEDDING_MODEL,
        input=text,
    )
    return resp.data[0].embedding


def build_doc_from_row(row: dict) -> tuple[str, str, dict]:
    """
    Turn a CSV row into (id, text, metadata).
    """
    framework = row.get("framework", "SOC2")
    control_id = row.get("control_id", "UNKNOWN")
    tsc = row.get("tsc_category", "")
    service = row.get("service", "")
    evidence_source = row.get("evidence_source", "")
    severity = row.get("severity", "LOW")
    summary = row.get("summary", "")
    remediation = row.get("remediation_recommended", "")
    details = row.get("details", "")
    timestamp = row.get("timestamp", "")

    text = (
        f"[framework: {framework}] [control_id: {control_id}] [TSC: {tsc}]\n\n"
        f"Summary: {summary}\n"
        f"Severity: {severity}\n"
        f"Evidence source: {evidence_source}\n"
        f"Service: {service}\n"
        f"Remediation recommended: {remediation}\n"
        f"Timestamp: {timestamp}\n\n"
        f"Details: {details}"
    )

    metadata = {
        "framework": framework,
        "control_id": control_id,
        "tsc_category": tsc,
        "service": service,
        "evidence_source": evidence_source,
        "severity": severity,
        "remediation_recommended": remediation,
        "timestamp": timestamp,
    }

    # unique ID per weekly record
    # (you can also include date or s3 key)
    id_ = f"{framework}-{control_id}-{timestamp or datetime.utcnow().isoformat()}"

    return id_, text, metadata


def lambda_handler(event, context):
    # S3 PUT event
    record = event["Records"][0]
    bucket = record["s3"]["bucket"]["name"]
    key = record["s3"]["object"]["key"]

    # Only ingest weekly CSVs
    if not key.startswith("weekly/") or not key.endswith(".csv"):
        return {"status": "ignored", "key": key}

    obj = s3.get_object(Bucket=bucket, Key=key)
    body = obj["Body"].read().decode("utf-8")

    reader = csv.DictReader(io.StringIO(body))

    vectors = []
    for i, row in enumerate(reader):
        id_, text, metadata = build_doc_from_row(row)
        embedding = embed_text(text)

        # attach additional metadata for traceability
        metadata["s3_key"] = key
        metadata["row_index"] = i

        vectors.append(
            {
                "id": id_,
                "values": embedding,
                "metadata": metadata,
            }
        )

    # Batch upsert to Pinecone
    if vectors:
        index.upsert(vectors=vectors)

    return {
        "status": "ok",
        "ingested": len(vectors),
        "s3_key": key,
    }
