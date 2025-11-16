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


# -----------------------------
# Pinecone Search
# -----------------------------

def search_evidence(query: str, top_k: int = 8) -> List[Dict[str, Any]]:
    """Embed the query and search Pinecone for top-k evidence chunks."""
    query_vec = embed_text(query)
    res = index.query(
        vector=query_vec,
        top_k=top_k,
        include_metadata=True,
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
You are a senior GRC engineer and AI governance auditor for FAFO, a SaaS company running in AWS.

You are helping external and internal auditors understand how FAFO maintains continuous compliance
for SOC 2 (with focus on CC6.x Logical Access, CC7.x Change Management and System Operations,
CC8.x Monitoring, and A- and C-series for Availability and Confidentiality), and ISO 27001.

You are given:
- Retrieved evidence chunks from a RAG knowledge base (weekly reports, remediation logs, Audit Manager exports).
- Each chunk includes framework, control_id, area, TSC domain, ISO mapping, service, severity, S3 evidence link, and a textual summary.

Your job:
- Answer the auditor's question using ONLY the provided context.
- Explicitly tie your explanation back to specific controls (e.g., CC6.1, CC7.2, A.9.2.3, etc.).
- Explain what the control is, how FAFO enforces/monitors it technically (Config, Security Hub, Audit Manager, Lambda, SCPs),
  and where the evidence lives (e.g., S3 evidence path, weekly report, remediation file, Audit Manager assessment).
- Be concise and structured, but detailed enough for an external auditor or CISO to understand the control design and operation.
- If the question asks about a time period, reference timestamps in the context where possible.
- If you do not have enough evidence in the context, clearly say so and recommend what additional evidence would be needed.

Never invent controls or evidence. If it's not in the context, say that it is not available in the retrieved evidence.
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
        page_title="FAFO Continuous Compliance – Auditor Q&A",
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
                matches = search_evidence(query, top_k=top_k)
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
