import json
import os
from typing import List, Dict

import boto3
import streamlit as st
from pinecone import Pinecone
from dotenv import load_dotenv

# Load .env file automatically
load_dotenv()

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", AWS_REGION)
EMBED_MODEL_ID = os.environ.get("BEDROCK_EMBED_MODEL_ID", "amazon.titan-embed-text-v2:0")
TEXT_MODEL_ID = os.environ.get("BEDROCK_TEXT_MODEL_ID", "amazon.titan-text-premier-v1:0")
PINECONE_API_KEY = os.environ["PINECONE_API_KEY"]
PINECONE_INDEX_NAME = os.environ.get("PINECONE_INDEX_NAME", "fafo-compliance-kb")

bedrock = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
pc = Pinecone(api_key=PINECONE_API_KEY)
index = pc.Index(PINECONE_INDEX_NAME)


def embed_text(query: str) -> List[float]:
    body = json.dumps({"inputText": query})
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
    raise RuntimeError(f"Unexpected embedding response: {resp_body.keys()}")


def bedrock_answer(question: str, contexts: List[Dict]) -> str:
    context_text = ""
    for i, ctx in enumerate(contexts, start=1):
        meta = ctx["metadata"]
        context_text += (
            f"[{i}] Framework={meta.get('framework')} "
            f"Control={meta.get('control_id')} "
            f"Service={meta.get('service')} "
            f"Severity={meta.get('severity')} "
            f"S3={meta.get('s3_uri')}\n"
            f"{ctx['content']}\n\n"
        )

    prompt = f"""You are an AI governance assistant for FAFO's continuous compliance platform.

The user is an auditor asking about SOC 2 / ISO 27001 evidence.

Using ONLY the evidence below, answer the question. 
Always:
- reference specific controls (e.g., CC6.1, A.9.2.3),
- mention relevant AWS services,
- point back to S3 evidence URIs when possible.

Evidence:
{context_text}

Question:
{question}

Answer as a concise paragraph, then list the key evidence items you used.
"""

    body = json.dumps(
        {
            "inputText": prompt,
            "textGenerationConfig": {
                "maxTokenCount": 512,
                "temperature": 0.2,
                "topP": 0.9,
                "stopSequences": [],
            },
        }
    )

    resp = bedrock.invoke_model(
        modelId=TEXT_MODEL_ID,
        body=body,
        contentType="application/json",
        accept="application/json",
    )
    out = json.loads(resp["body"].read())
    return out.get("outputText", "").strip()


def search_kb(query: str, top_k: int = 5, framework_filter: List[str] | None = None) -> List[Dict]:
    vec = embed_text(query)
    flt = {}
    if framework_filter:
        flt["framework"] = {"$in": framework_filter}

    res = index.query(
        vector=vec,
        top_k=top_k,
        include_metadata=True,
    )
    contexts: List[Dict] = []
    for m in res["matches"]:
        ctx = {
            "id": m["id"],
            "score": m["score"],
            "metadata": m.get("metadata", {}),
            "content": m.get("metadata", {}).get("text", ""),
        }
        # If you want to store the full chunk text in metadata as "text", you can
        # also change the indexer accordingly. For now, we’ll just rely on metadata
        # and not show the full content here.
        contexts.append(ctx)
    return contexts


def main():
    st.set_page_config(
        page_title="FAFO Auditor Q&A – Continuous Compliance RAG",
        layout="wide",
    )

    st.title("FAFO Inc. Continuous Compliance – Auditor Q&A")

    st.markdown(
        """
        Ask questions like:

        - *“Show me Security Hub findings for September affecting logical access (CC6.x).”*  
        - *“How are S3 public access issues remediated and evidenced?”*  
        - *“Summarize SOC 2 CC7.x operational monitoring findings for Q4.”*
        """
    )

    query = st.text_input("Auditor question", "")
    col1, col2 = st.columns(2)
    with col1:
        frameworks = st.multiselect(
            "Filter by framework",
            options=["SOC2", "ISO27001"],
            default=["SOC2"],
        )
    with col2:
        top_k = st.slider("Top-K evidence items", min_value=3, max_value=15, value=7)

    if st.button("Run query") and query.strip():
        with st.spinner("Searching FAFO evidence KB…"):
            contexts = search_kb(query, top_k=top_k, framework_filter=frameworks)

        if not contexts:
            st.warning("No evidence found for this query. Try broadening your question.")
            return

        # For now, we’ll just pass metadata into the LLM. You can later store
        # full text content in metadata["text"] from the indexer.
        answer = bedrock_answer(query, contexts)

        st.subheader("AI Governance Answer")
        st.write(answer)

        st.subheader("Evidence used")
        for i, ctx in enumerate(contexts, start=1):
            meta = ctx["metadata"]
            st.markdown(
                f"""
**[{i}] {meta.get('framework', '')} – {meta.get('control_id', '')}**

- Service: `{meta.get('service','')}`
- Severity: `{meta.get('severity','')}`
- Source type: `{meta.get('source','')}`
- S3 Evidence: `{meta.get('s3_uri','')}`
- Timestamp: `{meta.get('timestamp','')}`
- Score: `{ctx.get('score', 0):.4f}`
"""
            )


if __name__ == "__main__":
    main()
