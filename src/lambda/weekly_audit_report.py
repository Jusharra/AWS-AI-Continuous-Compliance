"""weekly_audit_report.py

Purpose
====================================================================
This file implements the **“Friday Excel”** Lambda. Its goal is to remove
the weekly grind of manually downloading screenshots and exporting CSV files
for your auditors. The Lambda performs five high-level steps every time it runs:

1. Download assessment metadata from AWS Audit Manager.
2. Gather evidence for each control (via evidence folders and items).
3. Calculate compliance status per control.
4. Generate an Excel workbook with multiple sheets using pandas + xlsxwriter.
5. Store the report in S3 and notify recipients via SES.
"""

import json
import boto3
import pandas as pd
from datetime import datetime, timedelta
from io import BytesIO
import logging
import os
import csv
from io import StringIO
from pathlib import Path

MAPPING_PATH = Path(__file__).resolve().parents[2] / "config" / "mappings" / "soc2_controls.csv"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_soc2_mapping():
    """
    Load your existing 28-control mapping from config/mappings/soc2_controls.csv.
    We DO NOT change that CSV; we only read it.
    """
    mapping = {}
    if not MAPPING_PATH.exists():
        logger.warning(f"SOC2 mapping file not found at {MAPPING_PATH} – weekly CSV will use raw ControlId.")
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


def infer_soc2_control_id(rec, mapping):
    """
    Try to normalize an Audit Manager control record to one of your 28 SOC2 IDs.

    Strategy:
    - If ControlId already equals one of your SOC2 IDs (CC6.1, A1.3, etc.), use it.
    - Else look for any SOC2 ID substring in ControlName or ControlSetName.
    - Fallback: return the raw ControlId (not ideal, but won’t break anything).
    """
    raw = (rec.get("ControlId") or "").strip()
    if raw in mapping:
        return raw

    name_blob = " ".join([
        rec.get("ControlName", "") or "",
        rec.get("ControlSetName", "") or "",
    ])

    for cid in mapping.keys():
        if cid in name_blob:
            return cid

    return raw  # fallback – still lets index_to_pinecone run, but won’t map cleanly

class AuditReportGenerator:
    """Generates comprehensive SOC 2 audit reports from AWS Audit Manager evidence."""
    
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
        self.sender_email = os.environ.get(
            "SENDER_EMAIL", "1stchoicecyber@gmail.com"
        )

    def fetch_assessment_evidence(self):
        """Retrieve complete assessment structure from AWS Audit Manager."""
        try:
            logger.info(f"Fetching assessment {self.assessment_id}")
            response = self.audit_manager.get_assessment(
                assessmentId=self.assessment_id
            )
            assessment = response["assessment"]
            logger.info(
                "Retrieved assessment with %d control sets",
                len(assessment["framework"]["controlSets"]),
            )
            return assessment
        except Exception as e:
            logger.error(f"Error fetching assessment: {e}")
            raise

    def collect_evidence_by_control(self, control_sets):
        """Collect the latest evidence for each SOC 2 control."""
        evidence_records = []
        evidence_cutoff = datetime.utcnow() - timedelta(days=7)

        for cs in control_sets:
            logger.info(f"Processing control set: {cs.get('name')}")
            for control in cs.get("controls", []):
                try:
                    folders = self.audit_manager.get_evidence_folders_by_assessment_control(
                        assessmentId=self.assessment_id,
                        controlSetId=cs["id"],
                        controlId=control["id"],
                    ).get("evidenceFolders", [])

                    if not folders:
                        evidence_records.append(
                            self._create_placeholder_record(cs, control)
                        )
                        continue

                    latest_evidence = []
                    for folder in folders:
                        if datetime.strptime(folder["date"], "%Y-%m-%d") >= evidence_cutoff.date():
                            items = self._fetch_evidence_items(
                                cs["id"], control["id"], folder["id"]
                            )
                            latest_evidence.extend(
                                self._process_evidence_items(
                                    items, cs, control, folder
                                )
                            )

                    # If nothing recent, take most recent folder
                    if not latest_evidence:
                        latest_folder = max(folders, key=lambda x: x["date"])
                        items = self._fetch_evidence_items(
                            cs["id"], control["id"], latest_folder["id"]
                        )
                        latest_evidence.extend(
                            self._process_evidence_items(
                                items, cs, control, latest_folder
                            )
                        )

                    evidence_records.extend(latest_evidence)

                except Exception as e:
                    logger.warning(
                        "Error processing control %s: %s", control["id"], e
                    )
                    evidence_records.append(
                        self._create_placeholder_record(cs, control, str(e))
                    )

        logger.info("Collected %d evidence records", len(evidence_records))
        return evidence_records

    def _process_evidence_items(self, items, cs, control, folder):
        processed = []
        for item in items:
            processed.append(
                {
                    "ControlSetName": cs.get("name"),
                    "ControlId": control["id"],
                    "ControlName": control.get("name"),
                    "EvidenceDate": folder.get("date"),
                    "EvidenceType": item.get("dataSource"),
                    "ComplianceStatus": self._determine_compliance_status(item),
                    "Finding": item.get("textResponse", ""),
                    "ResourceArn": self._extract_resource_arn(item),
                    "Severity": self._extract_severity(item),
                }
            )
        return processed

    def _fetch_evidence_items(self, cs_id, ctrl_id, folder_id):
        try:
            return self.audit_manager.get_evidence_by_evidence_folder(
                assessmentId=self.assessment_id,
                controlSetId=cs_id,
                evidenceFolderId=folder_id,
            ).get("evidence", [])
        except Exception as e:
            logger.warning(f"Error fetching evidence items: {e}")
            return []

    def _create_placeholder_record(self, cs, control, reason: str = "No evidence found"):
        return {
            "ControlSetName": cs.get("name"),
            "ControlId": control["id"],
            "ControlName": control.get("name"),
            "EvidenceDate": "No Evidence",
            "EvidenceType": "Manual Review Required",
            "ComplianceStatus": "UNKNOWN",
            "Finding": reason,
            "ResourceArn": "N/A",
            "Severity": "LOW",
        }

    def _determine_compliance_status(self, evidence):
        if "complianceCheck" in evidence:
            return evidence["complianceCheck"].get("status", "UNKNOWN").upper()
        if "findingComplianceStatus" in evidence.get("attributes", {}):
            return evidence["attributes"]["findingComplianceStatus"].upper()
        return "UNKNOWN"

    def _extract_resource_arn(self, evidence):
        res = evidence.get("resourcesIncluded", [])
        return res[0].get("arn", "N/A") if res else "N/A"

    def _extract_severity(self, evidence):
        if "findingSeverity" in evidence.get("attributes", {}):
            return evidence["attributes"]["findingSeverity"].upper()
        return (
            "MEDIUM"
            if self._determine_compliance_status(evidence) == "FAILED"
            else "LOW"
        )

    def generate_excel_report(self, evidence_records):
        df = pd.DataFrame(evidence_records)
        if df.empty:
            df = pd.DataFrame(
                [self._create_placeholder_record({}, {"id": "N/A", "name": "N/A"})]
            )

        excel_buffer = BytesIO()
        with pd.ExcelWriter(excel_buffer, engine="xlsxwriter") as writer:
            self._create_executive_summary_sheet(df, writer)
            self._create_control_status_sheet(df, writer)
            self._create_failed_findings_sheet(df, writer)
            df.to_excel(writer, sheet_name="All Evidence Details", index=False)
        excel_buffer.seek(0)
        return excel_buffer

    def generate_csv_summary_and_store(self, evidence_records):
            """
            Write a slimmed-down CSV for RAG indexing.

            Columns:
            - framework, control_id, service, severity, summary, details, timestamp

            Now normalized so:
            - control_id matches your SOC2 IDs (CC6.x, CC7.x, A1.x, C1.x) whenever possible
            - framework can be read from soc2_controls.csv if present (else defaults to SOC2)
            """
            if not evidence_records:
                logger.warning("No evidence records – CSV summary will be empty placeholder.")
                evidence_records = [self._create_placeholder_record({}, {'id': 'N/A', 'name': 'N/A'})]

            # Load your 28-control mapping once
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
                # Derive normalized SOC2 control ID
                soc2_id = infer_soc2_control_id(rec, soc2_mapping)

                # Derive service from ResourceArn if present
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

                # Pull framework from mapping if available; default to SOC2
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

            date_path = datetime.now().strftime("%Y/%m/%d")
            filename = f"SOC2_Weekly_Summary_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
            s3_key = f"weekly/{date_path}/{filename}"

            self.s3.put_object(
                Bucket=self.s3_bucket,
                Key=s3_key,
                Body=csv_buffer.getvalue().encode("utf-8"),
                ContentType="text/csv",
            )
            logger.info(f"Stored CSV summary in S3: s3://{self.s3_bucket}/{s3_key}")
            return s3_key

    def _create_executive_summary_sheet(self, df, writer):
        total = df["ControlId"].nunique()
        passed = df[df["ComplianceStatus"] == "PASSED"]["ControlId"].nunique()
        failed = df[df["ComplianceStatus"] == "FAILED"]["ControlId"].nunique()
        rate = (passed / total * 100) if total > 0 else 0
        summary_df = pd.DataFrame(
            {
                "Metric": [
                    "Total Controls",
                    "Passing",
                    "Failing",
                    "Compliance Rate (%)",
                    "Generated",
                ],
                "Value": [
                    total,
                    passed,
                    failed,
                    f"{rate:.1f}%",
                    datetime.now().strftime("%Y-%m-%d %H:%M"),
                ],
            }
        )
        summary_df.to_excel(
            writer, sheet_name="Executive Summary", index=False
        )

    def _create_control_status_sheet(self, df, writer):
        status_df = (
            df.groupby(["ControlSetName", "ControlId", "ControlName"])
            .agg(
                ComplianceStatus=("ComplianceStatus", "first"),
                EvidenceDate=("EvidenceDate", "max"),
            )
            .reset_index()
        )
        status_df.to_excel(writer, sheet_name="Control Status", index=False)

    def _create_failed_findings_sheet(self, df, writer):
        failed_df = df[df["ComplianceStatus"].isin(["FAILED", "WARNING"])].copy()
        if failed_df.empty:
            failed_df = pd.DataFrame([{"Status": "No failed findings"}])
        else:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            failed_df["SevSort"] = failed_df["Severity"].map(sev_order)
            failed_df = failed_df.sort_values("SevSort")
        failed_df.to_excel(writer, sheet_name="Failed Findings", index=False)

    def store_report_in_s3(self, excel_buffer):
        date_path = datetime.now().strftime('%Y/%m/%d')
        filename = f"SOC2_Weekly_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx"
        s3_key = f"weekly/{date_path}/{filename}"
        self.s3.put_object(Bucket=self.s3_bucket, Key=s3_key, Body=excel_buffer.getvalue())
        logger.info(f"Stored report in S3: s3://{self.s3_bucket}/{s3_key}")
        return s3_key


    def send_notification(self, s3_key):
        presigned_url = self.s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.s3_bucket, "Key": s3_key},
            ExpiresIn=604800,
        )
        subject = f"Weekly SOC 2 Audit Report - {datetime.now().strftime('%Y-%m-%d')}"
        body = (
            "The weekly SOC 2 compliance report is ready.\n\n"
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
        logger.info(
            "Sent notifications to %d recipients", len(self.report_recipients)
        )

def lambda_handler(event, context):
    generator = AuditReportGenerator(region=os.environ.get("AWS_REGION", "us-east-1"))
    assessment = generator.fetch_assessment_evidence()
    evidence_records = generator.collect_evidence_by_control(assessment)

    excel_buffer = generator.generate_excel_report(evidence_records)
    s3_excel_key = generator.store_report_in_s3(excel_buffer)

    csv_key = generator.generate_csv_summary_and_store(evidence_records)

    generator.send_notification(s3_excel_key)
    logger.info(f"Weekly Lambda completed. Excel: {s3_excel_key}, CSV: {csv_key}")
    return {
        "excel_report_key": s3_excel_key,
        "csv_summary_key": csv_key,
        "record_count": len(evidence_records),
    }

