# src/lambda/remediation_handler.py
import json
import logging
from typing import Any, Dict
from dotenv import load_dotenv
from modules import remediation_actions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

load_dotenv()
def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Entry point for the FAFO remediation Lambda.

    Triggered by EventBridge on Security Hub findings.
    """
    logger.info("Received event: %s", json.dumps(event))

    detail = event.get("detail") or {}
    findings = detail.get("findings") or []

    results = []
    for f in findings:
        try:
            result = remediation_actions.handle_finding(f)
        except Exception as e:
            logger.exception("Error handling finding %s: %s", f.get("Id"), e)
            result = "ERROR"

        results.append(
            {
                "finding_id": f.get("Id"),
                "result": result,
            }
        )

    logger.info("Remediation results: %s", json.dumps(results))
    return {
        "handled_findings": len(findings),
        "results": results,
    }
