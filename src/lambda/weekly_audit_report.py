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
            "REPORT_RECIPIENTS", "auditor@example.com"
        ).split(",")
        self.sender_email = os.environ.get("SENDER_EMAIL", "1stchoicecyber@gmail.com")

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

    def send_notification(self, s3_key: str) -> None:
        presigned_url = self.s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.s3_bucket, "Key": s3_key},
            ExpiresIn=604800,  # 7 days
        )
        subject = f"Weekly SOC 2 Audit Report - {datetime.utcnow().strftime('%Y-%m-%d')}"
        body = (
            "The weekly SOC 2 compliance CSV report is ready.\n\n"
            f"Download (expires in 7 days):\n{presigned_url}"
        )
        self.ses.send_email(
            Source=self.sender_email,
            Destination={"ToAddresses": self.report_recipients},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": body}},
            },
        )
        logger.info("Sent notifications to %d recipients", len(self.report_recipients))


# -------------------------------------------------------------------
# Lambda entry point
# -------------------------------------------------------------------

def lambda_handler(event, context):
    generator = AuditReportGenerator(region=os.environ.get("AWS_REGION", "us-east-1"))

    assessment = generator.fetch_assessment_evidence()
    control_sets = assessment["framework"]["controlSets"]
    evidence_records = generator.collect_evidence_by_control(control_sets)

    # CSV-only report (no pandas/xlsxwriter/Excel)
    csv_key = generator.generate_csv_summary_and_store(evidence_records)

    generator.send_notification(csv_key)
    logger.info("Weekly Lambda completed. CSV: %s", csv_key)
    return {
        "csv_summary_key": csv_key,
        "record_count": len(evidence_records),
    }
