#!/usr/bin/env python3
"""
Index FAFO evidence into Pinecone for RAG-based auditor Q&A.

Sources:
- S3 evidence bucket (weekly GRC reports, remediation evidence)
- SOC2 mapping CSV (config/mappings/soc2_controls.csv)

Stored metadata includes:
- framework (SOC2/ISO)
- control_id
- tsc_domain
- area (Logical Access, Change Mgmt, etc.)
- iso_control_id
- service
- severity
- s3_uri
- timestamp
- full text chunk (for RAG)
"""

import csv
import json
import os
from pathlib import Path
from typing import Dict, List, Tuple

import boto3
import botocore
from pinecone import Pinecone, ServerlessSpec, Index

# -----------------------------
# ENV + GLOBALS
# -----------------------------
MAPPING_PATH = Path("config/mappings/soc2_controls.csv")

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", AWS_REGION)
EVIDENCE_BUCKET = os.environ["FAFO_EVIDENCE_BUCKET"]

PINECONE_API_KEY = os.environ["PINECONE_API_KEY"]
PINECONE_INDEX_NAME = os.environ.get("PINECONE_INDEX_NAME", "fafo-compliance-kb")
EMBED_MODEL_ID = os.environ.get("BEDROCK_EMBED_MODEL_ID", "amazon.titan-embed-text-v2:0")

s3 = boto3.client("s3", region_name=AWS_REGION)
bedrock = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)


# -----------------------------
# Load SOC 2 Mapping
# -----------------------------
def load_soc2_mapping() -> Dict[str, Dict]:
    mapping: Dict[str, Dict] = {}

    if not MAPPING_PATH.exists():
        print(f"[WARN] Mapping not found at {MAPPING_PATH}")
        return mapping

    with MAPPING_PATH.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = row.get("soc2_control_id", "").strip()
            if cid:
                mapping[cid] = row

    print(f"[INFO] Loaded {len(mapping)} SOC2 control mappings from {MAPPING_PATH}")
    return mapping


# -----------------------------
# Pinecone Index
# -----------------------------
def ensure_index() -> Index:
    pc = Pinecone(api_key=PINECONE_API_KEY)
    existing = [idx["name"] for idx in pc.list_indexes()]

    if PINECONE_INDEX_NAME not in existing:
        print(f"[INFO] Creating Pinecone index: {PINECONE_INDEX_NAME}")
        pc.create_index(
            name=PINECONE_INDEX_NAME,
            dimension=1024,
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),
        )

    return pc.Index(PINECONE_INDEX_NAME)


# -----------------------------
# Bedrock Embedder
# -----------------------------
def embed_text(text: str) -> List[float]:
    body = json.dumps({"inputText": text})

    resp = bedrock.invoke_model(
        modelId=EMBED_MODEL_ID,
        body=body,
        contentType="application/json",
        accept="application/json",
    )

    resp_body = json.loads(resp["body"].read())

    if "embedding" in resp_body:
        return resp_body["embedding"]

    if "embeddingsByType" in resp_body and "float" in resp_body["embeddingsByType"]:
        return resp_body["embeddingsByType"]["float"]

    raise RuntimeError(f"Unexpected Bedrock embedding response: {resp_body}")


# -----------------------------
# S3 Helpers
# -----------------------------
def list_s3_objects(prefix: str) -> List[Dict]:
    objs = []
    token = None

    while True:
        kwargs = {"Bucket": EVIDENCE_BUCKET, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token

        resp = s3.list_objects_v2(**kwargs)
        objs.extend(resp.get("Contents", []))

        if resp.get("IsTruncated"):
            token = resp["NextContinuationToken"]
        else:
            break

    return objs


def fetch_object_text(key: str) -> str:
    obj = s3.get_object(Bucket=EVIDENCE_BUCKET, Key=key)
    return obj["Body"].read().decode("utf-8", errors="ignore")


# -----------------------------
# Weekly CSV → Chunks
# -----------------------------
def build_chunks_from_weekly_csv(key: str, mapping: Dict[str, Dict]) -> List[Tuple[str, str, Dict]]:
    s3_uri = f"s3://{EVIDENCE_BUCKET}/{key}"
    text = fetch_object_text(key)
    rows = list(csv.DictReader(text.splitlines()))

    chunks = []

    for i, row in enumerate(rows):
        control_id = row.get("control_id", "").strip() or row.get("ControlId", "").strip()
        mapped = mapping.get(control_id, {})

        # Merge mapping + row data
        framework = mapped.get("framework", "SOC2")
        tsc_domain = mapped.get("tsc_domain", "")
        area = mapped.get("area", "")
        iso_control_id = mapped.get("iso_control_id", "")
        service = row.get("service") or mapped.get("aws_mechanism_type", "Unknown")
        severity = row.get("severity", "Info")
        ts = row.get("timestamp", "")

        body = (
            f"Framework: {framework}\n"
            f"SOC2 Control: {control_id}\n"
            f"TSC Domain: {tsc_domain}\n"
            f"Area: {area}\n"
            f"ISO Control: {iso_control_id}\n"
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
            "tsc_domain": tsc_domain,
            "area": area,
            "iso_control_id": iso_control_id,
            "service": service,
            "severity": severity,
            "s3_uri": s3_uri,
            "timestamp": ts,
            "source": "weekly_report",
            "line": i,
            "text": body,
        }

        doc_id = f"{key}#row-{i}"
        chunks.append((doc_id, body, metadata))

    return chunks


# -----------------------------
# Remediation JSON → Chunks
# -----------------------------
def build_chunks_from_remediation_json(key: str, mapping: Dict[str, Dict]) -> List[Tuple[str, str, Dict]]:
    s3_uri = f"s3://{EVIDENCE_BUCKET}/{key}"

    data = json.loads(fetch_object_text(key))
    ts = data.get("timestamp", "")
    finding = data.get("finding", {}) or {}
    product_fields = finding.get("ProductFields", {}) or {}

    control_id = (
        product_fields.get("aws/securityhub/ControlId")
        or product_fields.get("ControlId")
        or ""
    )

    mapped = mapping.get(control_id, {})

    title = finding.get("Title", "")
    desc = finding.get("Description", "")
    severity = (finding.get("Severity") or {}).get("Label", "INFO")
    area = mapped.get("area", "")
    tsc_domain = mapped.get("tsc_domain", "")
    iso_control_id = mapped.get("iso_control_id", "")

    body = (
        f"Remediation evidence for control {control_id} ({area}).\n"
        f"Title: {title}\n"
        f"Description: {desc}\n"
        f"Action: {data.get('action_status','')}\n"
        f"Severity: {severity}\n"
        f"S3 Evidence: {s3_uri}\n"
        f"Timestamp: {ts}"
    )

    metadata = {
        "framework": "SOC2",
        "control_id": control_id,
        "tsc_domain": tsc_domain,
        "area": area,
        "iso_control_id": iso_control_id,
        "service": "SecurityHub",
        "severity": severity,
        "s3_uri": s3_uri,
        "timestamp": ts,
        "source": "remediation",
        "text": body,
    }

    return [(key, body, metadata)]


# -----------------------------
# MAIN INDEXER
# -----------------------------
def index_all():
    mapping = load_soc2_mapping()
    index = ensure_index()
    vectors = []

    # Weekly summaries (CSV)
    weekly_objs = list_s3_objects("weekly/")
    for obj in weekly_objs:
        key = obj["Key"]
        if key.endswith(".csv"):
            for doc_id, content, metadata in build_chunks_from_weekly_csv(key, mapping):
                emb = embed_text(content)
                vectors.append({"id": doc_id, "values": emb, "metadata": metadata})

    # Remediation evidence (JSON)
    remediation_objs = list_s3_objects("remediation/")
    for obj in remediation_objs:
        key = obj["Key"]
        if key.endswith(".json"):
            for doc_id, content, metadata in build_chunks_from_remediation_json(key, mapping):
                emb = embed_text(content)
                vectors.append({"id": doc_id, "values": emb, "metadata": metadata})

    if not vectors:
        print("[INFO] No vectors to upsert – nothing indexed.")
        return

    print(f"[INFO] Upserting {len(vectors)} vectors into Pinecone index {PINECONE_INDEX_NAME}...")
    batch_size = 100

    for i in range(0, len(vectors), batch_size):
        batch = vectors[i:i+batch_size]
        index.upsert(vectors=batch)
        print(f"[INFO] Upserted batch {i//batch_size + 1}")

    print("[INFO] Indexing complete.")


if __name__ == "__main__":
    index_all()
