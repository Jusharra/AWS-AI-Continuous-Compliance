#!/usr/bin/env python3
"""
Index FAFO evidence into Pinecone for RAG-based auditor Q&A.

Sources:
- S3 evidence bucket (weekly GRC reports, remediation evidence, Audit Manager exports)
- Local controls mapping (docs/controls.md) [optional future enhancement]

Each chunk is stored with metadata:
- framework (SOC2 / ISO27001)
- control_id (e.g., CC6.1, A.9.2.3)
- service (SecurityHub, Config, AuditManager, Lambda)
- s3_uri
- timestamp
"""

import csv
import json
import os
from pathlib import Path
from typing import Dict, List, Tuple

import boto3
from pinecone import Pinecone, ServerlessSpec, Index

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", AWS_REGION)
EVIDENCE_BUCKET = os.environ["FAFO_EVIDENCE_BUCKET"]

PINECONE_API_KEY = os.environ["PINECONE_API_KEY"]
PINECONE_INDEX_NAME = os.environ.get("PINECONE_INDEX_NAME", "fafo-compliance-kb")
EMBED_MODEL_ID = os.environ.get("BEDROCK_EMBED_MODEL_ID", "amazon.titan-embed-text-v2:0")

s3 = boto3.client("s3", region_name=AWS_REGION)
bedrock = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)


def ensure_index() -> Index:
    pc = Pinecone(api_key=PINECONE_API_KEY)

    # Titan v2 default dimension is 1024 :contentReference[oaicite:0]{index=0}
    if PINECONE_INDEX_NAME not in [idx["name"] for idx in pc.list_indexes()]:
        pc.create_index(
            name=PINECONE_INDEX_NAME,
            dimension=1024,
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),
        )

    return pc.Index(PINECONE_INDEX_NAME)


def embed_text(text: str) -> List[float]:
    """Call Amazon Titan Text Embeddings via Bedrock."""
    body = json.dumps({"inputText": text})
    resp = bedrock.invoke_model(
        modelId=EMBED_MODEL_ID,
        body=body,
        contentType="application/json",
        accept="application/json",
    )
    resp_body = json.loads(resp["body"].read())
    # Titan v2 returns "embedding" or "embeddingsByType" depending on version :contentReference[oaicite:1]{index=1}
    if "embedding" in resp_body:
        return resp_body["embedding"]
    if "embeddingsByType" in resp_body and "float" in resp_body["embeddingsByType"]:
        return resp_body["embeddingsByType"]["float"]
    raise RuntimeError(f"Unexpected embedding response format: {resp_body.keys()}")


def list_s3_objects(prefix: str) -> List[Dict]:
    """List objects under a prefix in the evidence bucket."""
    objs: List[Dict] = []
    continuation = None
    while True:
        kwargs = {"Bucket": EVIDENCE_BUCKET, "Prefix": prefix}
        if continuation:
            kwargs["ContinuationToken"] = continuation
        resp = s3.list_objects_v2(**kwargs)
        for o in resp.get("Contents", []):
            objs.append(o)
        if resp.get("IsTruncated"):
            continuation = resp.get("NextContinuationToken")
        else:
            break
    return objs


def fetch_object_text(key: str) -> str:
    resp = s3.get_object(Bucket=EVIDENCE_BUCKET, Key=key)
    body = resp["Body"].read().decode("utf-8", errors="ignore")
    return body


def build_chunks_from_weekly_csv(key: str) -> List[Tuple[str, str, Dict]]:
    """
    Example: weekly GRC CSV with columns like:
    framework,control_id,service,severity,summary,details,timestamp
    """
    s3_uri = f"s3://{EVIDENCE_BUCKET}/{key}"
    text = fetch_object_text(key)
    rows = list(csv.DictReader(text.splitlines()))
    chunks: List[Tuple[str, str, Dict]] = []

    for i, row in enumerate(rows):
        framework = row.get("framework", "SOC2")
        control_id = row.get("control_id", "")
        service = row.get("service", "Unknown")
        severity = row.get("severity", "Info")
        ts = row.get("timestamp", "")

        content = (
            f"Framework: {framework}\n"
            f"Control: {control_id}\n"
            f"Service: {service}\n"
            f"Severity: {severity}\n"
            f"Summary: {row.get('summary','')}\n"
            f"Details: {row.get('details','')}\n"
            f"Evidence: {s3_uri}\n"
            f"Timestamp: {ts}"
        )

        metadata = {
            "framework": framework,
            "control_id": control_id,
            "service": service,
            "severity": severity,
            "s3_uri": s3_uri,
            "source": "weekly_report",
            "timestamp": ts,
            "line": i,
        }
        doc_id = f"{key}#row-{i}"
        chunks.append((doc_id, content, metadata))

    return chunks


def build_chunks_from_remediation_json(key: str) -> List[Tuple[str, str, Dict]]:
    """
    Remediation evidence written by remediation Lambda:
    {
      "timestamp": "...",
      "action_status": "...",
      "finding": { ... Security Hub finding ... }
    }
    """
    s3_uri = f"s3://{EVIDENCE_BUCKET}/{key}"
    raw = fetch_object_text(key)
    data = json.loads(raw)

    ts = data.get("timestamp", "")
    finding = data.get("finding", {})
    product_fields = finding.get("ProductFields", {}) or {}

    control_id = (
        product_fields.get("aws/securityhub/ControlId")
        or product_fields.get("ControlId")
        or ""
    )
    title = finding.get("Title", "")
    desc = finding.get("Description", "")
    severity = (finding.get("Severity") or {}).get("Label", "INFO")
    service = "SecurityHub"

    content = (
        f"Remediation evidence for control {control_id}.\n"
        f"Security Hub title: {title}\n"
        f"Description: {desc}\n"
        f"Action status: {data.get('action_status','')}\n"
        f"Severity: {severity}\n"
        f"Evidence S3 URI: {s3_uri}\n"
        f"Timestamp: {ts}"
    )

    metadata = {
        "framework": "SOC2",
        "control_id": control_id,
        "service": service,
        "severity": severity,
        "s3_uri": s3_uri,
        "source": "remediation",
        "timestamp": ts,
    }

    doc_id = f"{key}"
    return [(doc_id, content, metadata)]


def index_all():
    index = ensure_index()

    # 1) Weekly GRC reports (you can adjust prefix to match how your Lambda writes)
    weekly_objs = list_s3_objects(prefix="weekly/")
    # 2) Remediation evidence
    remediation_objs = list_s3_objects(prefix="remediation/")

    vectors = []

    for obj in weekly_objs:
        key = obj["Key"]
        if not key.endswith(".csv"):
            continue
        for doc_id, content, metadata in build_chunks_from_weekly_csv(key):
            emb = embed_text(content)
            vectors.append(
                {
                    "id": doc_id,
                    "values": emb,
                    "metadata": metadata,
                }
            )

    for obj in remediation_objs:
        key = obj["Key"]
        if not key.endswith(".json"):
            continue
        for doc_id, content, metadata in build_chunks_from_remediation_json(key):
            emb = embed_text(content)
            vectors.append(
                {
                    "id": doc_id,
                    "values": emb,
                    "metadata": metadata,
                }
            )

    if not vectors:
        print("[INFO] No vectors to upsert – nothing indexed.")
        return

    print(f"[INFO] Upserting {len(vectors)} vectors into Pinecone index {PINECONE_INDEX_NAME}...")
    # Upsert in batches of 100
    batch_size = 100
    for i in range(0, len(vectors), batch_size):
        batch = vectors[i : i + batch_size]
        index.upsert(vectors=batch)
        print(f"[INFO] Upserted batch {i//batch_size + 1}")

    print("[INFO] Indexing complete.")


if __name__ == "__main__":
    index_all()
