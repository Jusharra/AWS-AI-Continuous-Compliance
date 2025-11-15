"""gitlab_to_asff.py

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

def load_gitlab_findings(filename: str):
    """Load GitLab security scan results from JSON report file."""
    try:
        with open(filename, "r") as f:
            gitlab_report = json.load(f)
        return gitlab_report.get("vulnerabilities", [])
    except FileNotFoundError:
        print(f"No {filename} found, skipping...")
        return []

def transform_to_asff(finding, product_name, region, aws_account):
    """Transform a GitLab finding into ASFF format for Security Hub."""
    now = datetime.datetime.utcnow().isoformat() + "Z"

    severity_map = {
        "Critical": "CRITICAL",
        "High": "HIGH",
        "Medium": "MEDIUM",
        "Low": "LOW",
        "Info": "INFORMATIONAL",
    }

    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"{product_name}-{finding.get('id', 'unknown')}",
        "ProductArn": (
            f"arn:aws:securityhub:{region}:{aws_account}:product/{aws_account}/default"
        ),
        "GeneratorId": f"{product_name}-Scanner",
        "AwsAccountId": aws_account,
        "Types": ["Software and Configuration Checks/Vulnerabilities"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {
            "Label": severity_map.get(
                finding.get("severity", "Unknown"), "INFORMATIONAL"
            )
        },
        "Title": finding.get("name", f"{product_name} Security Finding"),
        "Description": finding.get(
            "description", "Security vulnerability detected"
        ),
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

def send_to_security_hub(asff_findings, region: str = "us-east-1"):
    """Send ASFF findings to AWS Security Hub."""
    if not asff_findings:
        print("No findings to send to Security Hub")
        return

    sh_client = boto3.client("securityhub", region_name=region)

    batch_size = 100
    for i in range(0, len(asff_findings), batch_size):
        batch = asff_findings[i : i + batch_size]
        response = sh_client.batch_import_findings(Findings=batch)
        print(
            f"Sent batch {i//batch_size + 1}: "
            f"{response['SuccessCount']} successful, "
            f"{response['FailureCount']} failed"
        )

if __name__ == "__main__":
    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    aws_account = os.environ.get("AWS_ACCOUNT_ID", "123456789012")

    sast_report_file = "gl-sast-report.json"
    dast_report_file = "gl-dast-report.json"

    sast_findings = load_gitlab_findings(sast_report_file)
    dast_findings = load_gitlab_findings(dast_report_file)

    all_findings_asff = []

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
        print(f"Successfully processed {len(all_findings_asff)} security findings")
    else:
        print("No security findings detected in scans")
