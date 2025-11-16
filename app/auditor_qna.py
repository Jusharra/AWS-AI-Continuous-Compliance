#!/usr/bin/env python3
"""
FAFO Continuous Compliance – Auditor Q&A (Streamlit + RAG)

- Uses Pinecone as the vector store for evidence & control mappings.
- Uses Amazon Titan v2 text embeddings via Bedrock for query embeddings.
- Uses Anthropic Claude 3.5 Sonnet via Anthropic API for answer generation.
- Designed for SOC 2 / ISO 27001 auditors asking questions like:
  "Show me logical access evidence for CC6.3 in September" or
  "How are change management controls monitored and evidenced?"
"""

import json
import os
from typing import List, Dict, Any

import boto3
import streamlit as st
from dotenv import load_dotenv
from pinecone import Pinecone, Index
from anthropic import Anthropic
import re
from retriever_hybrid import pinecone_hybrid_search, build_sparse_vector
from pinecone_text.sparse import BM25Encoder

bm25 = BM25Encoder().default()

# -----------------------------
# Environment & Clients
# -----------------------------

load_dotenv()

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", AWS_REGION)
EMBED_MODEL_ID = os.environ.get("BEDROCK_EMBED_MODEL_ID", "amazon.titan-embed-text-v2:0")

PINECONE_API_KEY = os.environ["PINECONE_API_KEY"]
PINECONE_INDEX_NAME = os.environ.get("PINECONE_INDEX_NAME", "fafo-compliance-kb")

anthropic_key = os.getenv("ANTHROPIC_API_KEY")
CLAUDE_MODEL_ID = "claude-sonnet-4-5-20250929"
CONTROL_ID_REGEX = re.compile(r"\b(CC\d+\.\d+|C\d+\.\d+|A\.\d+\.\d+)\b", re.IGNORECASE)

bedrock = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
pc = Pinecone(api_key=PINECONE_API_KEY)
index: Index = pc.Index(PINECONE_INDEX_NAME)
anthropic_client = Anthropic(api_key=anthropic_key)


# -----------------------------
# Embeddings (Bedrock Titan)
# -----------------------------

def embed_text(text: str) -> List[float]:
    """Generate a Titan v2 embedding for the query text."""
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
    raise RuntimeError(f"Unexpected Titan embedding response: {resp_body}")

def extract_control_ids(question: str) -> list[str]:
    matches = CONTROL_ID_REGEX.findall(question)
    # Normalize like CC6.3, CC7.2 etc.
    return [m.upper().replace("A.", "A.").replace("C", "C") for m in matches]

# -----------------------------
# Pinecone Search
# -----------------------------
def pinecone_hybrid_search(index, query_text: str, top_k: int = 8):
    # dense embedding via Titan (same as index)
    dense = embed_text(query_text)  # reuse your existing Bedrock embed helper
    # sparse embedding via BM25
    sparse = bm25.encode_queries(query_text)

    res = index.query(
        vector=dense,
        sparse_vector=sparse,
        top_k=top_k,
        include_metadata=True,
    )

    hits = []
    for m in res.matches or []:
        md = m.metadata or {}
        hits.append(
            {
                "score": float(m.score),
                "text": md.get("text", ""),
                "framework": md.get("framework", "SOC2"),
                "control_id": md.get("control_id", ""),
                "area": md.get("area", ""),
                "iso_control_id": md.get("iso_control_id", ""),
                "s3_uri": md.get("s3_uri", ""),
            }
        )
    return hits

def search_evidence(query: str, top_k: int = 8) -> List[Dict[str, Any]]:
    """Embed the query and search Pinecone for top-k evidence chunks.
       If the question references specific controls (CC6.3, CC7.x, A.*, C.*),
       use a metadata filter on control_id to tighten relevance.
    """
    control_ids = extract_control_ids(query)
    query_vec = embed_text(query)

    filter_obj = None
    if control_ids:
        filter_obj = {"control_id": {"$in": control_ids}}

    res = index.query(
        vector=query_vec,
        top_k=top_k,
        include_metadata=True,
        filter=filter_obj,   # only applied when control_ids is non-empty
    )
    return res.matches or []



def format_context_for_prompt(matches: List[Dict[str, Any]]) -> str:
    """Render Pinecone matches into a textual context block for the LLM."""
    if not matches:
        return "No evidence chunks were retrieved from the knowledge base."

    lines = []
    for i, m in enumerate(matches, start=1):
        md = m.metadata or {}
        control_id = md.get("control_id", "Unknown")
        framework = md.get("framework", "SOC2")
        area = md.get("area", "")
        tsc_domain = md.get("tsc_domain", "")
        iso_id = md.get("iso_control_id", "")
        service = md.get("service", "")
        severity = md.get("severity", "")
        s3_uri = md.get("s3_uri", "")
        source = md.get("source", "")
        timestamp = md.get("timestamp", "")
        text = md.get("text", "")

        lines.append(
            f"Chunk #{i}:\n"
            f"- Framework: {framework}\n"
            f"- SOC2 Control: {control_id}\n"
            f"- TSC Domain: {tsc_domain}\n"
            f"- Area: {area}\n"
            f"- ISO Control: {iso_id}\n"
            f"- Service: {service}\n"
            f"- Severity: {severity}\n"
            f"- Source: {source}\n"
            f"- Evidence S3 URI: {s3_uri}\n"
            f"- Timestamp: {timestamp}\n"
            f"- Evidence Text: {text}\n"
        )

    return "\n\n".join(lines)


# -----------------------------
# Claude Answer (Anthropic API)
# -----------------------------

SYSTEM_PROMPT = """
You are a senior GRC engineer answering auditor-style questions using SOC 2 and ISO 27001 evidence from Pinecone.

Rules:
- Always ground answers in the retrieved chunks (Security Hub, Config, Audit Manager, weekly CSVs, remediation JSON).
- Make the mapping explicit:
  - SOC 2 CC6.x  → Logical access controls (identity, MFA, RBAC, least privilege).
  - SOC 2 CC7.x  → Change management (CI/CD, infra-as-code, controlled releases).
  - SOC 2 CC8.x  → System operations (monitoring, incident handling, remediation).
  - A1.x         → Availability controls.
  - C1.x         → Confidentiality controls.

When you answer:
1) Start with a short executive summary in auditor language.
2) Then map to controls (CC6.x / CC7.x / CC8.x / A1.x / C1.x and ISO 27001 IDs) using the metadata fields:
   - control_id, tsc_domain, area, iso_control_id, aws_mechanism_type, aws_mechanism.
3) Call out which AWS evidence you used:
   - Security Hub findings, Config rules, Audit Manager assessments, weekly reports CSV, remediation JSON, etc.
4) If evidence is missing or incomplete, explicitly say what is missing and what evidence would be needed.

Never invent control mappings that are not present in the metadata.
If a question is about CC6.3, prefer chunks whose control_id = CC6.3.
""".strip()


def build_prompt(question: str, context_block: str) -> str:
    return (
        "Auditor question:\n"
        f"{question}\n\n"
        "Retrieved evidence context:\n"
        f"{context_block}\n\n"
        "Using only the evidence above, provide an auditor-ready answer. "
        "Structure your answer as:\n"
        "1) Summary answer\n"
        "2) Relevant controls and how they are implemented\n"
        "3) Evidence locations (S3 paths, reports, assessments)\n"
        "4) Any gaps or limitations in the retrieved evidence\n"
    )


def claude_answer(question: str, matches: List[Dict[str, Any]]) -> str:
    """Call Anthropic Claude with the auditor query + evidence context."""
    context_block = format_context_for_prompt(matches)
    user_prompt = build_prompt(question, context_block)

    try:
        resp = anthropic_client.messages.create(
            model=CLAUDE_MODEL_ID,
            max_tokens=1200,
            temperature=0.2,
            messages=[
                {
                    "role": "user",
                    "content": user_prompt,
                }
            ],
            system=SYSTEM_PROMPT,
        )
        # Anthropic SDK returns a list of content blocks; we want the text pieces.
        parts = []
        for block in resp.content:
            if block.type == "text":
                parts.append(block.text)
        return "\n".join(parts).strip() or "[No response content returned from Claude.]"
    except Exception as e:
        return f"[ERROR] Claude call failed: {e}"


# -----------------------------
# Streamlit UI
# -----------------------------

def main():
    st.set_page_config(
        page_title="FAFO Inc. Continuous Compliance – Auditor Q&A",
        layout="wide",
    )

    st.title("FAFO Continuous Compliance – Auditor Q&A")
    st.caption(
        "Ask questions about SOC 2 / ISO 27001 controls, logical access, change management, "
        "system operations, availability, and confidentiality. Backed by AWS evidence & RAG."
    )

    with st.sidebar:
        st.subheader("Query Options")
        top_k = st.slider("Top-K Evidence Chunks", min_value=3, max_value=15, value=8)
        st.markdown("---")
        st.markdown("**Context Filters (future enhancement):**")
        st.text("Current build: no filters applied.\n"
                "Next iteration: filter by control_id, area, timeframe, etc.")

    query = st.text_area(
        "Enter your auditor-style question:",
        placeholder=(
            "Examples:\n"
            "- How is logical access (CC6.3) enforced for production AWS accounts?\n"
            "- Show me evidence that change management (CC7.x) is monitored weekly.\n"
            "- What documentation exists for availability controls (A-series) in September?\n"
            "- How are confidentiality controls for customer data evidenced?"
        ),
        height=140,
    )

    if st.button("Run Query", type="primary"):
        if not query.strip():
            st.warning("Please enter a question first.")
            return

        with st.spinner("Retrieving evidence from Pinecone and generating answer with Claude..."):
            try:
                matches = pinecone_hybrid_search(index, query, top_k=top_k)
            except Exception as e:
                st.error(f"Error searching Pinecone: {e}")
                return

            if not matches:
                st.warning("No evidence was retrieved from the knowledge base.")
                return

            answer = claude_answer(query, matches)

        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("LLM Answer (Claude)")
            st.write(answer)

        with col2:
            st.subheader("Retrieved Evidence Chunks")
            for i, m in enumerate(matches, start=1):
                md = m.metadata or {}
                with st.expander(f"Chunk #{i} – {md.get('control_id', 'Unknown control')}"):
                    st.json(md)


if __name__ == "__main__":
    main()
