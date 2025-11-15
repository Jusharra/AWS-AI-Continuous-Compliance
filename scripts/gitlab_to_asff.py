"""
gitlab_to_asff.py

This script is designed to run inside a GitLab CI/CD pipeline after your
security scanning stages (for example, SAST and DAST).

It:
1. Loads JSON reports produced by GitLab security scans.
2. Converts each finding into the AWS Security Finding Format (ASFF).
3. Calls Security Hub BatchImportFindings to ingest them.
"""

import json
import boto3
import datetime
import os
from typing import List, Dict


def load_gitlab_findings(report_path: str) -> list[dict]:
    """
    Load GitLab SAST/DAST findings from a JSON report.

    Returns an empty list if the file is missing, empty, or invalid JSON.
    """
    if not os.path.exists(report_path):
        print(f"[INFO] Report not found: {report_path} – treating as no findings.")
        return []

    if os.path.getsize(report_path) == 0:
        print(f"[INFO] Report is empty: {report_path} – treating as no findings.")
        return []

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[WARN] JSON decode failed for {report_path}: {e} – treating as no findings.")
        return []

    findings = data.get("vulnerabilities", []) or []
    print(f"[INFO] Loaded {len(findings)} findings from {report_path}")
    return findings


def transform_to_asff(finding: dict, product_name: str, region: str, aws_account: str) -> dict:
    """Transform a GitLab finding into ASFF format for Security Hub."""
    now = datetime.datetime.utcnow().isoformat() + "Z"

    severity_map = {
        "Critical": "CRITICAL",
        "High": "HIGH",
        "Medium": "MEDIUM",
        "Low": "LOW",
        "Info": "INFORMATIONAL",
    }

    severity_label = severity_map.get(finding.get("severity", "Unknown"), "INFORMATIONAL")

    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"{product_name}-{finding.get('id', 'unknown')}",
        "ProductArn": f"arn:aws:securityhub:{region}:{aws_account}:product/{aws_account}/default",
        "GeneratorId": f"{product_name}-Scanner",
        "AwsAccountId": aws_account,
        "Types": ["Software and Configuration Checks/Vulnerabilities"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {"Label": severity_label},
        "Title": finding.get("name", f"{product_name} Security Finding"),
        "Description": finding.get("description", "Security vulnerability detected"),
        "Resources": [
            {
                "Type": "Other",
                "Id": finding.get("location", {}).get("file", "Unknown file"),
            }
        ],
        "Remediation": {
            "Recommendation": {
                "Text": finding.get(
                    "solution",
                    "Review GitLab security report for remediation guidance",
                )
            }
        },
        "RecordState": "ACTIVE",
        "WorkflowState": "NEW",
    }


def send_to_security_hub(asff_findings: list[dict], region: str = "us-east-1") -> None:
    """Send ASFF findings to AWS Security Hub."""
    if not asff_findings:
        print("No findings to send to Security Hub.")
        return

    sh_client = boto3.client("securityhub", region_name=region)
    batch_size = 100

    for i in range(0, len(asff_findings), batch_size):
        batch = asff_findings[i : i + batch_size]
        response = sh_client.batch_import_findings(Findings=batch)
        print(
            f"Sent batch {i // batch_size + 1}: "
            f"{response['SuccessCount']} successful, "
            f"{response['FailureCount']} failed"
        )


if __name__ == "__main__":
    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    aws_account = os.environ.get("AWS_ACCOUNT_ID", "123456789012")

    # Load findings from GitLab reports generated in the previous CI job
    sast_findings = load_gitlab_findings("gl-sast-report.json")
    dast_findings = load_gitlab_findings("gl-dast-report.json")

    all_findings = sast_findings + dast_findings

    if not all_findings:
        print("No security findings detected in SAST/DAST reports – nothing to send to Security Hub.")
        raise SystemExit(0)

    # Transform to ASFF
    all_findings_asff: list[dict] = []

    for finding in sast_findings:
        all_findings_asff.append(
            transform_to_asff(finding, "GitLab-SAST", region, aws_account)
        )

    for finding in dast_findings:
        all_findings_asff.append(
            transform_to_asff(finding, "GitLab-DAST", region, aws_account)
        )

    if all_findings_asff:
        send_to_security_hub(all_findings_asff, region)
        print(f"Successfully processed {len(all_findings_asff)} security findings.")
    else:
        print("No security findings detected in scans.")
