# src/lambda/modules/remediation_actions.py
"""
Event-driven remediation actions for Security Hub findings.

Current supported control(s):
- S3 public access findings (FSBP / CIS controls, e.g. S3.1).
"""

import datetime
import json
import logging
import os
from typing import Any, Dict

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
securityhub = boto3.client("securityhub")

EVIDENCE_BUCKET = os.environ.get("FAFO_EVIDENCE_BUCKET")


def _extract_control_id(finding: Dict[str, Any]) -> str:
    """Try to pull a useful control ID from the finding."""
    pf = finding.get("ProductFields", {}) or {}
    return (
        pf.get("aws/securityhub/ControlId")
        or pf.get("ControlId")
        or pf.get("RuleId")
        or ""
    )


def _extract_s3_bucket_name(finding: Dict[str, Any]) -> str | None:
    """Get the S3 bucket name from the finding resources."""
    for res in finding.get("Resources", []):
        if res.get("Type") == "AwsS3Bucket":
            details = (res.get("Details") or {}).get("AwsS3Bucket", {})
            return details.get("Name") or res.get("Id")
    return None


def remediate_s3_public_access(finding: Dict[str, Any]) -> str:
    """
    Enforce S3 Block Public Access on the offending bucket.
    This aligns with FSBP S3.* and CIS S3 public access controls.
    """
    bucket_name = _extract_s3_bucket_name(finding)
    if not bucket_name:
        logger.warning("No S3 bucket resource found in finding; skipping")
        return "SKIPPED_NO_BUCKET"

    logger.info("Enforcing Block Public Access on bucket %s", bucket_name)

    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    return f"ENFORCED_BLOCK_PUBLIC_ACCESS:{bucket_name}"


def _record_evidence(finding: Dict[str, Any], action_status: str) -> None:
    """Write a remediation evidence record to the FAFO evidence bucket."""
    if not EVIDENCE_BUCKET:
        logger.info("FAFO_EVIDENCE_BUCKET not set; skipping evidence write")
        return

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_id = finding.get("Id", "unknown").replace(":", "_")
    key = f"remediation/{ts}-{safe_id}.json"

    body = {
        "timestamp": ts,
        "action_status": action_status,
        "finding": finding,
    }

    logger.info("Writing remediation evidence to s3://%s/%s", EVIDENCE_BUCKET, key)
    s3.put_object(
        Bucket=EVIDENCE_BUCKET,
        Key=key,
        Body=json.dumps(body, default=str).encode("utf-8"),
    )


def _update_finding_status(finding: Dict[str, Any], note_text: str) -> None:
    """Mark the finding as RESOLVED in Security Hub with a note."""
    try:
        securityhub.batch_update_findings(
            FindingIdentifiers=[
                {
                    "Id": finding["Id"],
                    "ProductArn": finding["ProductArn"],
                }
            ],
            Workflow={"Status": "RESOLVED"},
            Note={
                "Text": note_text,
                "UpdatedBy": "fafo-remediation-lambda",
            },
        )
        logger.info("Updated Security Hub finding %s to RESOLVED", finding["Id"])
    except Exception as e:
        logger.exception("Failed to update Security Hub finding: %s", e)


def handle_finding(finding: Dict[str, Any]) -> str:
    """
    Dispatch remediation based on control ID.
    Returns a status string describing what happened.
    """
    control_id = _extract_control_id(finding)
    logger.info("Handling finding %s (control_id=%s)", finding.get("Id"), control_id)

    # Expand this mapping as you add more auto-fixes
    if control_id in ("S3.1", "S3_BUCKET_PUBLIC_READ_PROHIBITED"):
        status = remediate_s3_public_access(finding)
    else:
        logger.info("No remediation registered for control_id=%s", control_id)
        status = f"UNSUPPORTED_CONTROL:{control_id or 'UNKNOWN'}"

    # Evidence + finding workflow update
    _record_evidence(finding, status)
    if status.startswith("ENFORCED_"):
        _update_finding_status(finding, status)

    return status
