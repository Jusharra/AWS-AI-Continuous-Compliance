"""weekly_audit_report.py

Purpose
====================================================================
This file implements the **“Friday Report”** Lambda. Its goal is to remove
the weekly grind of manually downloading screenshots and exporting CSV files
for your auditors. The Lambda performs these steps:

1. Download assessment metadata from AWS Audit Manager.
2. Gather evidence for each control (via evidence folders and items).
3. Calculate compliance status per control.
4. Generate a weekly CSV summary aligned with your SOC 2 control mapping.
5. Store the CSV in S3 under weekly/ and notify recipients via SES.
"""

import csv
import json
import logging
import os
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Dict, List, Any
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from collections import Counter


# -------------------------------------------------------------------
# Paths & logging
# -------------------------------------------------------------------

MAPPING_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "mappings" / "soc2_controls.csv"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------
# SOC 2 mapping helpers
# -------------------------------------------------------------------

def load_soc2_mapping() -> Dict[str, Dict[str, str]]:
    """
    Load your existing 28-control mapping from config/mappings/soc2_controls.csv.
    We DO NOT change that CSV; we only read it.
    """
    mapping: Dict[str, Dict[str, str]] = {}
    if not MAPPING_PATH.exists():
        logger.warning(
            "SOC2 mapping file not found at %s – weekly CSV will use raw ControlId.",
            MAPPING_PATH,
        )
        return mapping

    with MAPPING_PATH.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = (row.get("soc2_control_id") or "").strip()
            if not cid:
                continue
            mapping[cid] = row

    logger.info("Loaded %d SOC2 controls from %s", len(mapping), MAPPING_PATH)
    return mapping


def infer_soc2_control_id(rec: Dict[str, Any], mapping: Dict[str, Dict]) -> str:
    """
    Try to normalize an Audit Manager control record to one of your SOC2 IDs.

    Strategy:
    - If ControlId already equals one of your SOC2 IDs (CC6.1, A1.3, etc.), use it.
    - Else look for any SOC2 ID substring in ControlName or ControlSetName.
    - Fallback: return the raw ControlId.
    """
    raw = (rec.get("ControlId") or "").strip()
    if raw in mapping:
        return raw

    name_blob = " ".join(
        [
            rec.get("ControlName", "") or "",
            rec.get("ControlSetName", "") or "",
        ]
    )

    for cid in mapping.keys():
        if cid in name_blob:
            return cid

    return raw  # fallback – still indexable, but not mapped cleanly


# -------------------------------------------------------------------
# Core generator
# -------------------------------------------------------------------

class AuditReportGenerator:
    """Generates weekly SOC 2 audit CSV reports from AWS Audit Manager evidence."""

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.audit_manager = boto3.client("auditmanager", region_name=region)
        self.s3 = boto3.client("s3", region_name=region)
        self.ses = boto3.client("ses", region_name=region)

        # Configuration - pulled from environment variables
        self.assessment_id = os.environ.get(
            "ASSESSMENT_ID", "faeae42c-09e6-4251-a0e3-28e5e021fcd2"
        )
        self.s3_bucket = os.environ.get("S3_BUCKET", "fafo-audit-reports")
        self.report_recipients = os.environ.get(
            "REPORT_RECIPIENTS", "qjgoree@gmail.com"
        ).split(",")
        self.sender_email = os.environ.get("SENDER_EMAIL", "1stchoicecyber@gmail.com")

        # -------------------------------------------------------
        #  NEW: Bedrock client for AI-written recommendations
        # -------------------------------------------------------
        self.bedrock = boto3.client("bedrock-runtime", region_name=region)

        # Model can be overridden via ENV, otherwise Claude Sonnet
        self.bedrock_model_id = os.environ.get(
            "BEDROCK_CLAUDE_MODEL_ID",
            "anthropic.claude-3-sonnet-20240229-v1:0"
        )


    # ------------------------- Audit Manager ------------------------- #

    def fetch_assessment_evidence(self) -> Dict[str, Any]:
        """Retrieve complete assessment structure from AWS Audit Manager."""
        try:
            logger.info("Fetching assessment %s", self.assessment_id)
            response = self.audit_manager.get_assessment(
                assessmentId=self.assessment_id
            )
            assessment = response["assessment"]
            control_sets = assessment["framework"]["controlSets"]
            logger.info("Retrieved assessment with %d control sets", len(control_sets))
            return assessment
        except Exception as e:
            logger.error("Error fetching assessment: %s", e)
            raise

    def collect_evidence_by_control(self, control_sets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collect the latest evidence for each SOC 2 control."""
        evidence_records: List[Dict[str, Any]] = []
        evidence_cutoff = datetime.utcnow().date() - timedelta(days=7)

        for cs in control_sets:
            if not isinstance(cs, dict):
                logger.warning("Unexpected control set type: %r", cs)
                continue

            cs_name = cs.get("name", "Unknown Control Set")
            cs_id = cs.get("id")
            logger.info("Processing control set: %s", cs_name)

            for control in cs.get("controls", []):
                ctrl_id = control.get("id")
                ctrl_name = control.get("name")

                try:
                    folders = self.audit_manager.get_evidence_folders_by_assessment_control(
                        assessmentId=self.assessment_id,
                        controlSetId=cs_id,
                        controlId=ctrl_id,
                    ).get("evidenceFolders", [])

                    if not folders:
                        evidence_records.append(
                            self._create_placeholder_record(
                                cs_name, ctrl_id, ctrl_name
                            )
                        )
                        continue

                    latest_evidence: List[Dict[str, Any]] = []

                    # Prefer folders in the last 7 days
                    for folder in folders:
                        folder_date_str = folder.get("date")
                        try:
                            folder_date = datetime.strptime(
                                folder_date_str, "%Y-%m-%d"
                            ).date()
                        except Exception:
                            folder_date = evidence_cutoff  # treat as "old but usable"

                        if folder_date >= evidence_cutoff:
                            items = self._fetch_evidence_items(cs_id, ctrl_id, folder["id"])
                            latest_evidence.extend(
                                self._process_evidence_items(
                                    items, cs_name, ctrl_id, ctrl_name, folder
                                )
                            )

                    # If nothing recent, fall back to most recent folder overall
                    if not latest_evidence:
                        latest_folder = max(folders, key=lambda x: x.get("date", ""))
                        items = self._fetch_evidence_items(cs_id, ctrl_id, latest_folder["id"])
                        latest_evidence.extend(
                            self._process_evidence_items(
                                items, cs_name, ctrl_id, ctrl_name, latest_folder
                            )
                        )

                    evidence_records.extend(latest_evidence)

                except Exception as e:
                    logger.warning("Error processing control %s: %s", ctrl_id, e)
                    evidence_records.append(
                        self._create_placeholder_record(
                            cs_name, ctrl_id, ctrl_name, reason=str(e)
                        )
                    )

        logger.info("Collected %d evidence records", len(evidence_records))
        return evidence_records

    def _fetch_evidence_items(self, cs_id: str, ctrl_id: str, folder_id: str) -> List[Dict[str, Any]]:
        try:
            resp = self.audit_manager.get_evidence_by_evidence_folder(
                assessmentId=self.assessment_id,
                controlSetId=cs_id,
                evidenceFolderId=folder_id,
            )
            return resp.get("evidence", []) or []
        except Exception as e:
            logger.warning("Error fetching evidence items: %s", e)
            return []

    def _process_evidence_items(
        self,
        items: List[Dict[str, Any]],
        cs_name: str,
        ctrl_id: str,
        ctrl_name: str,
        folder: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        processed: List[Dict[str, Any]] = []
        folder_date = folder.get("date", "")

        for item in items:
            processed.append(
                {
                    "ControlSetName": cs_name,
                    "ControlId": ctrl_id,
                    "ControlName": ctrl_name,
                    "EvidenceDate": folder_date,
                    "EvidenceType": item.get("dataSource"),
                    "ComplianceStatus": self._determine_compliance_status(item),
                    "Finding": item.get("textResponse", ""),
                    "ResourceArn": self._extract_resource_arn(item),
                    "Severity": self._extract_severity(item),
                }
            )
        return processed

    def _create_placeholder_record(
        self,
        cs_name: str,
        ctrl_id: str,
        ctrl_name: str,
        reason: str = "No evidence found",
    ) -> Dict[str, Any]:
        return {
            "ControlSetName": cs_name,
            "ControlId": ctrl_id,
            "ControlName": ctrl_name,
            "EvidenceDate": "No Evidence",
            "EvidenceType": "Manual Review Required",
            "ComplianceStatus": "UNKNOWN",
            "Finding": reason,
            "ResourceArn": "N/A",
            "Severity": "LOW",
        }

    def _determine_compliance_status(self, evidence: Dict[str, Any]) -> str:
        if "complianceCheck" in evidence:
            return evidence["complianceCheck"].get("status", "UNKNOWN").upper()
        attrs = evidence.get("attributes", {}) or {}
        if "findingComplianceStatus" in attrs:
            return attrs["findingComplianceStatus"].upper()
        return "UNKNOWN"

    def _extract_resource_arn(self, evidence: Dict[str, Any]) -> str:
        res = evidence.get("resourcesIncluded", []) or []
        return res[0].get("arn", "N/A") if res else "N/A"

    def _extract_severity(self, evidence: Dict[str, Any]) -> str:
        attrs = evidence.get("attributes", {}) or {}
        if "findingSeverity" in attrs:
            return attrs["findingSeverity"].upper()
        return "MEDIUM" if self._determine_compliance_status(evidence) == "FAILED" else "LOW"

    # -------------------------- CSV summary -------------------------- #

    def generate_csv_summary_and_store(self, evidence_records: List[Dict[str, Any]]) -> str:
        """
        Write a slimmed-down CSV for RAG indexing.

        Columns:
        - framework, control_id, service, severity, summary, details, timestamp

        Normalization:
        - control_id matches SOC2 IDs (CC6.x, CC7.x, A1.x, C1.x) whenever possible
        - framework read from soc2_controls.csv when available (else defaults to SOC2)
        """
        if not evidence_records:
            logger.warning("No evidence records – CSV summary will be empty placeholder.")
            evidence_records = [
                self._create_placeholder_record("N/A", "N/A", "N/A")
            ]

        soc2_mapping = load_soc2_mapping()

        csv_buffer = StringIO()
        fieldnames = [
            "framework",
            "control_id",
            "service",
            "severity",
            "summary",
            "details",
            "timestamp",
        ]
        writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
        writer.writeheader()

        for rec in evidence_records:
            soc2_id = infer_soc2_control_id(rec, soc2_mapping)

            arn = rec.get("ResourceArn", "") or ""
            if "s3" in arn:
                service = "S3"
            elif "config" in arn:
                service = "Config"
            elif "securityhub" in arn:
                service = "SecurityHub"
            elif "lambda" in arn:
                service = "Lambda"
            else:
                service = "Unknown"

            meta = soc2_mapping.get(soc2_id, {})
            framework = meta.get("framework", "SOC2")

            writer.writerow(
                {
                    "framework": framework,
                    "control_id": soc2_id,
                    "service": service,
                    "severity": rec.get("Severity", "LOW"),
                    "summary": rec.get("Finding", ""),
                    "details": f"{rec.get('ControlName','')} in {rec.get('ControlSetName','')} – {rec.get('EvidenceType','')}",
                    "timestamp": rec.get("EvidenceDate", ""),
                }
            )

        csv_buffer.seek(0)

        date_path = datetime.utcnow().strftime("%Y/%m/%d")
        filename = f"SOC2_Weekly_Summary_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.csv"
        s3_key = f"weekly/{date_path}/{filename}"

        self.s3.put_object(
            Bucket=self.s3_bucket,
            Key=s3_key,
            Body=csv_buffer.getvalue().encode("utf-8"),
            ContentType="text/csv",
        )
        logger.info("Stored CSV summary in S3: s3://%s/%s", self.s3_bucket, s3_key)
        return s3_key

    # ---------------------------- Email ------------------------------ #
    
    def compute_summary_metrics(self, evidence_records):
        """
        Compute simple executive-level metrics from the evidence records.
        Returns a dict with totals and a short text summary.
        """
        if not evidence_records:
            return {
                "total_controls": 0,
                "passed_controls": 0,
                "failed_controls": 0,
                "unknown_controls": 0,
                "summary_text": "No evidence records were collected for this run.",
            }

        # Unique controls overall
        all_controls = {rec.get("ControlId") for rec in evidence_records if rec.get("ControlId")}
        total_controls = len(all_controls)

        # Controls by status (using first status we see per control)
        status_by_control = {}
        for rec in evidence_records:
            cid = rec.get("ControlId")
            status = (rec.get("ComplianceStatus") or "UNKNOWN").upper()
            if not cid:
                continue
            # Only set once – first status wins
            status_by_control.setdefault(cid, status)

        passed_controls = {c for c, s in status_by_control.items() if s == "PASSED"}
        failed_controls = {c for c, s in status_by_control.items() if s == "FAILED"}
        unknown_controls = {c for c, s in status_by_control.items() if s not in ("PASSED", "FAILED")}

        compliance_rate = 0.0
        if total_controls > 0:
            compliance_rate = (len(passed_controls) / total_controls) * 100.0

        # Build a short, human-readable summary string
        summary_lines = [
            f"Total controls evaluated: {total_controls}",
            f"Passing controls: {len(passed_controls)}",
            f"Failing controls: {len(failed_controls)}",
            f"Unknown / manual review: {len(unknown_controls)}",
            f"Overall compliance rate: {compliance_rate:.1f}%",
        ]

        # Optionally call out up to 5 failing controls
        if failed_controls:
            top_failed = sorted(list(failed_controls))[:5]
            summary_lines.append("")
            summary_lines.append("Sample failing controls (up to 5):")
            for cid in top_failed:
                summary_lines.append(f"- {cid}")

        return {
            "total_controls": total_controls,
            "passed_controls": len(passed_controls),
            "failed_controls": len(failed_controls),
            "unknown_controls": len(unknown_controls),
            "compliance_rate": compliance_rate,
            "summary_text": "\n".join(summary_lines),
        }
  
    def build_summary(self, evidence_records):
        """
        Build a simple executive summary from evidence records.
        """
        # Unique controls (by ControlId)
        control_ids = {rec.get("ControlId") for rec in evidence_records if rec.get("ControlId")}
        total_controls = len(control_ids)

        passing_ids = {
            rec.get("ControlId")
            for rec in evidence_records
            if rec.get("ComplianceStatus") == "PASSED"
        }
        failing_ids = {
            rec.get("ControlId")
            for rec in evidence_records
            if rec.get("ComplianceStatus") == "FAILED"
        }

        passed_controls = len(passing_ids)
        failed_controls = len(failing_ids)
        unknown_controls = max(total_controls - passed_controls - failed_controls, 0)

        compliance_rate = (passed_controls / total_controls * 100.0) if total_controls else 0.0

        # Rough “risk” counters – you can tweak this later
        critical_high = sum(
            1
            for rec in evidence_records
            if rec.get("ComplianceStatus") == "FAILED"
            and rec.get("Severity", "").upper() in ("CRITICAL", "HIGH")
        )
        medium = sum(
            1
            for rec in evidence_records
            if rec.get("ComplianceStatus") == "FAILED"
            and rec.get("Severity", "").upper() == "MEDIUM"
        )

        return {
            "total_controls": total_controls,
            "passed_controls": passed_controls,
            "failed_controls": failed_controls,
            "unknown_controls": unknown_controls,
            "compliance_rate": compliance_rate,
            "critical_high": critical_high,
            "medium": medium,
        }
    def build_ai_recommendations(self, summary: dict) -> str:
        """
        Use Claude via Bedrock to generate short, exec-level key recommendations.

        Returns markdown bullet points. Falls back to static text if Bedrock fails.
        """
        prompt = f"""
You are a senior cloud security and GRC engineer.

You are writing the **Key Recommendations** section of a weekly SOC 2 audit email
for a CISO and audit team. You are given the weekly compliance snapshot:

- Total controls evaluated: {summary['total_controls']}
- Passing controls: {summary['passed_controls']}
- Failing controls: {summary['failed_controls']}
- Unknown / manual review: {summary['unknown_controls']}
- Overall compliance rate: {summary['compliance_rate']:.1f}%
- Failed findings with Critical/High severity: {summary['critical_high']}
- Failed findings with Medium severity: {summary['medium']}

Write 3–5 short bullet points grouped by priority:

- High Priority
- Medium Priority
- Ongoing

Each bullet should be 1–2 sentences, focused on **what to do next week**
(remediation, owners, and monitoring). Do NOT restate the raw numbers, and do NOT
mention that an AI wrote this. Keep it under 150 words total.

Return ONLY markdown bullet points (no headings, no intro, no outro).
"""

        try:
            body = json.dumps(
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": [{"type": "text", "text": prompt}],
                        }
                    ],
                    "max_tokens": 300,
                    "temperature": 0.2,
                }
            )

            resp = self.bedrock.invoke_model(
                modelId=self.bedrock_model_id,
                body=body,
            )
            resp_body = json.loads(resp["body"].read())
            # Anthropic-style response
            content = resp_body["output"]["message"]["content"]
            text_parts = [c["text"] for c in content if c.get("type") == "text"]
            text = "\n".join(text_parts).strip()

            if not text:
                raise ValueError("Empty Bedrock response")

            return text

        except (BotoCoreError, ClientError, KeyError, ValueError, Exception) as e:
            logger.warning(f"Bedrock recommendations failed, using static text. Error: {e}")
            # Fallback: static bullets (very similar to what you had)
            return (
                "- **High Priority:** Review and address all FAILED controls with Critical/High severity. "
                "Confirm ownership and open remediation tickets in your GRC backlog.\n"
                "- **Medium Priority:** Work through remaining FAILED controls with Medium severity, "
                "focusing on production accounts and internet-exposed resources.\n"
                "- **Ongoing:** Maintain weekly monitoring of AWS Config, Security Hub, and Audit Manager. "
                "Re-run this report after major changes or incidents."
            )
    def _compute_summary_metrics(self, evidence_records):
        """Compute simple exec-summary stats from the evidence list."""
        # Unique controls by ID
        control_ids = {rec.get("ControlId") for rec in evidence_records if rec.get("ControlId")}
        total_controls = len(control_ids)

        passed_controls = {
            rec.get("ControlId")
            for rec in evidence_records
            if rec.get("ComplianceStatus") == "PASSED"
        }
        failed_controls = {
            rec.get("ControlId")
            for rec in evidence_records
            if rec.get("ComplianceStatus") == "FAILED"
        }

        passing = len(passed_controls)
        failing = len(failed_controls)
        unknown = max(total_controls - passing - failing, 0)

        # Severity breakdown for failed findings
        failed_severities = Counter(
            (rec.get("Severity", "LOW") or "LOW").upper()
            for rec in evidence_records
            if rec.get("ComplianceStatus") == "FAILED"
        )

        compliance_rate = (passing / total_controls * 100.0) if total_controls > 0 else 0.0

        return {
            "total_controls": total_controls,
            "passing": passing,
            "failing": failing,
            "unknown": unknown,
            "compliance_rate": compliance_rate,
            "failed_severities": failed_severities,
        }

    def _build_email_body(self, evidence_records, presigned_url: str) -> str:
        """
        Build an AWS-Access-Review-style email body:
        - Title
        - Executive Summary
        - Key Recommendations
        - Next Steps
        """
        metrics = self._compute_summary_metrics(evidence_records)

        total = metrics["total_controls"]
        passing = metrics["passing"]
        failing = metrics["failing"]
        unknown = metrics["unknown"]
        rate = metrics["compliance_rate"]
        failed_severities = metrics["failed_severities"]

        crit = failed_severities.get("CRITICAL", 0)
        high = failed_severities.get("HIGH", 0)
        medium = failed_severities.get("MEDIUM", 0)
        low = failed_severities.get("LOW", 0)

        today_str = datetime.utcnow().strftime("%Y-%m-%d")

        body = f"""AWS Access Review Report

# AWS Access Review Report

## Executive Summary

This automated weekly report summarizes the current SOC 2 control posture for your AWS environment as of {today_str}.

- Total controls evaluated: {total}
- Passing controls: {passing}
- Failing controls: {failing}
- Unknown / manual review: {unknown}
- Overall compliance rate: {rate:.1f}%

Failed findings by severity:
- Critical: {crit}
- High: {high}
- Medium: {medium}
- Low: {low}

## Key Recommendations

1. **High Priority:** Review all controls with Critical or High severity failed findings and create remediation tasks for each.
2. **Medium Priority:** Address Medium severity findings as part of your regular sprint or weekly maintenance cycle.
3. **Low Priority:** Track Low severity issues for long-term hardening and defense-in-depth improvements.
4. **Ongoing:** Maintain regular evidence collection, report reviews, and configuration monitoring to prevent control drift.

## Next Steps

For detailed findings and specific recommendations, please review the attached CSV report or download it using the link below:

{presigned_url}

If this report was generated as part of a demo environment, replace the recipient list with your production security and GRC contacts.

---
This report was generated automatically by the FAFO Continuous Compliance engine.
"""

        return body

    def send_notification(self, s3_key, summary):
        """
        Send an executive-style email summary + CSV download link.

        `summary` is the dict returned by build_summary().
        """
        # Generate presigned URL to the CSV summary
        presigned_url = self.s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.s3_bucket, "Key": s3_key},
            ExpiresIn=604800,  # 7 days
        )

        today = datetime.now().strftime("%Y-%m-%d")
        subject = f"Weekly SOC 2 Audit Summary – {today}"

        # Ask Claude (via Bedrock) for Key Recommendations
        ai_recommendations = self.build_ai_recommendations(summary)

        body = f"""Weekly SOC 2 Audit Summary – {today}

# Weekly SOC 2 Audit Summary

## Executive Summary

Your weekly SOC 2 compliance snapshot is ready.

- Total controls evaluated: {summary['total_controls']}
- Passing controls: {summary['passed_controls']}
- Failing controls: {summary['failed_controls']}
- Unknown / manual review: {summary['unknown_controls']}
- Overall compliance rate: {summary['compliance_rate']:.1f}%

## Key Recommendations

{ai_recommendations}

## Next Steps

- Download the full CSV evidence summary for detailed, control-by-control review:
  {presigned_url}

For each failing control, confirm ownership, create remediation tickets,
and track progress in your GRC backlog.

---

This report was generated automatically by the FAFO Continuous Compliance engine.
"""

        self.ses.send_email(
            Source=self.sender_email,
            Destination={"ToAddresses": self.report_recipients},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": body}},
            },
        )
        logger.info(
            "Sent notifications to %d recipients", len(self.report_recipients)
        )





# -------------------------------------------------------------------
# Lambda entry point
# -------------------------------------------------------------------

def lambda_handler(event, context):
    generator = AuditReportGenerator(region=os.environ.get("AWS_REGION", "us-east-1"))

    assessment = generator.fetch_assessment_evidence()
    control_sets = assessment["framework"]["controlSets"]
    evidence_records = generator.collect_evidence_by_control(control_sets)

    # Build executive summary stats
    summary = generator.build_summary(evidence_records)

    # CSV-only report (no pandas/xlsxwriter/Excel)
    csv_key = generator.generate_csv_summary_and_store(evidence_records)

    # Send nicely formatted executive summary email + link
    generator.send_notification(csv_key, summary)

    logger.info(f"Weekly Lambda completed. CSV: {csv_key}")
    return {
        "csv_summary_key": csv_key,
        "record_count": len(evidence_records),
    }




