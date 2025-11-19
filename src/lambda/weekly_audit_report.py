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
from datetime import datetime, timedelta, date
from io import StringIO
from pathlib import Path
from typing import Dict, List, Any
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from collections import Counter
from botocore.config import Config
from dotenv import load_dotenv

load_dotenv()

BEDROCK_REGION = os.environ.get("BEDROCK_REGION", os.environ.get("AWS_REGION", "us-east-1"))
BEDROCK_CLAUDE_MODEL_ID = os.environ.get(
    "BEDROCK_CLAUDE_MODEL_ID",
    "claude-sonnet-4-5-20250929",  # Claude 3 Sonnet on Bedrock
)

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
        self.s3 = boto3.client(
            "s3",
            region_name=region,
            config=Config(signature_version="s3v4"),
        )
        self.ses = boto3.client("ses", region_name=region)
        self.bedrock = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)

        # Configuration - pulled from environment variables
        self.assessment_id = os.environ.get(
            "ASSESSMENT_ID", "faeae42c-09e6-4251-a0e3-28e5e021fcd2"
        )
        self.s3_bucket = os.environ.get("S3_BUCKET", "fafo-continuous-compliance-evidence-281517525855")
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
            "anthropic.claude-sonnet-4-5-20250929"
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

    def collect_evidence_by_control(self, control_sets):
        """Collect the latest evidence for each SOC 2 control."""
        evidence_records = []
        evidence_cutoff_date = (datetime.utcnow() - timedelta(days=7)).date()

        for cs in control_sets:
            cs_name = cs.get("name", "Unknown control set")
            cs_id = cs.get("id")
            logger.info(f"Processing control set: {cs_name}")

            for control in cs.get("controls", []):
                ctrl_id = control.get("id")
                ctrl_name = control.get("name", "Unknown control")

                try:
                    resp = self.audit_manager.get_evidence_folders_by_assessment_control(
                        assessmentId=self.assessment_id,
                        controlSetId=cs_id,
                        controlId=ctrl_id,
                    )
                    folders = resp.get("evidenceFolders", []) or []

                    if not folders:
                        # No folders at all → placeholder
                        evidence_records.append(
                            self._create_placeholder_record(
                                cs_name,
                                ctrl_id,
                                ctrl_name,
                                "No evidence folders found",
                            )
                        )
                        continue

                    latest_evidence: list[dict] = []

                    # Prefer folders from the last 7 days
                    for folder in folders:
                        raw_date = folder.get("date")
                        folder_date = self._parse_folder_date(raw_date)

                        if folder_date is not None and folder_date >= evidence_cutoff_date:
                            items = self._fetch_evidence_items(
                                cs_id, ctrl_id, folder.get("id")
                            )
                            latest_evidence.extend(
                                self._process_evidence_items(items, cs, control, folder)
                            )

                    # If nothing recent, fall back to the most recent folder by date
                    if not latest_evidence:
                        latest_folder = max(
                            folders,
                            key=lambda f: self._parse_folder_date(f.get("date")) or date.min,
                        )
                        items = self._fetch_evidence_items(
                            cs_id, ctrl_id, latest_folder.get("id")
                        )
                        latest_evidence.extend(
                            self._process_evidence_items(
                                items, cs, control, latest_folder
                            )
                        )

                    evidence_records.extend(latest_evidence)

                except Exception as e:
                    logger.warning(
                        "Error processing control %s (%s): %s", ctrl_id, ctrl_name, e
                    )
                    evidence_records.append(
                        self._create_placeholder_record(
                            cs_name,
                            ctrl_id,
                            ctrl_name,
                            f"Error collecting evidence: {e}",
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

    def _extract_control_code(self, ctrl_name: str, ctrl_id: str) -> str:
        """
        Try to get a human-friendly control code (e.g. 'PI1.4') from the control name.
        Falls back to the raw Audit Manager id if we can't parse it.
        """
        if not ctrl_name:
            return ctrl_id or "UNKNOWN"

        # Many SOC 2 controls look like "PI1.4: The entity implements..."
        parts = ctrl_name.split(":", 1)
        if len(parts) > 1:
            code = parts[0].strip()
            if code:
                return code

        return ctrl_id or ctrl_name

    def _process_evidence_items(self, items, cs, control, folder):
        """Normalize raw Audit Manager evidence items into our flat record shape."""
        processed = []
        cs_name = cs.get("name", "Unknown control set")
        ctrl_id = control.get("id")
        ctrl_name = control.get("name", "Unknown control")

        folder_date = self._parse_folder_date(folder.get("date"))
        folder_date_str = folder_date.isoformat() if folder_date else "No Evidence"

        # Use a human-readable control code instead of the UUID
        control_code = self._extract_control_code(ctrl_name, ctrl_id)

        for item in items or []:
            processed.append(
                {
                    "ControlSetName": cs_name,
                    "ControlId": control_code,   # <— this is what will end up in Excel
                    "ControlName": ctrl_name,
                    "EvidenceDate": folder_date_str,
                    "EvidenceType": item.get("dataSource"),
                    "ComplianceStatus": self._determine_compliance_status(item),
                    "Finding": item.get("textResponse", "")
                    or item.get("notes", "")
                    or "No evidence text available",
                    "ResourceArn": self._extract_resource_arn(item),
                    "Severity": self._extract_severity(item),
                }
            )
        return processed

    def _parse_folder_date(self, raw_date):
        """Safely parse Audit Manager folder date into a date object (or None)."""
        if raw_date is None:
            return None

        if isinstance(raw_date, datetime):
            # Use date-only to avoid datetime/date comparison issues
            return raw_date.date()

        if isinstance(raw_date, date):
            return raw_date

        if isinstance(raw_date, str):
            try:
                # Audit Manager usually uses YYYY-MM-DD
                return datetime.strptime(raw_date, "%Y-%m-%d").date()
            except ValueError:
                logger.warning(f"Unexpected folder date format: {raw_date}")
                return None

        return None


    def _create_placeholder_record(
        self,
        cs_name: str,
        ctrl_id: str,
        ctrl_name: str = "Unknown control",
        reason: str = "No evidence found",
    ):
        """
        Build a placeholder evidence record when we can't pull real evidence.

        cs_name  – name of the control set (e.g., 'Logical and Physical Access Controls')
        ctrl_id  – control identifier (e.g., 'CC6.3' or raw Audit Manager Id)
        ctrl_name – friendly control name
        reason   – why this is a placeholder (shown in the 'summary' column)
        """
        control_code = self._extract_control_code(ctrl_name, ctrl_id)

        return {
            "ControlSetName": cs_name,
            "ControlId": control_code,          # friendly code if possible
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

    def _derive_service_from_record(self, rec: Dict[str, Any]) -> str:
        """
        Best-effort mapping of AWS service from EvidenceType / ResourceArn.
        Keeps 'Unknown' only when we really can't infer anything.
        """
        evidence_type = (rec.get("EvidenceType") or "").upper()
        arn = (rec.get("ResourceArn") or "").lower()

        if "s3" in arn or evidence_type.startswith("S3"):
            return "S3"
        if "iam" in arn or evidence_type.startswith("IAM"):
            return "IAM"
        if "cloudtrail" in arn:
            return "CloudTrail"
        if "ec2" in arn:
            return "EC2"
        if "rds" in arn:
            return "RDS"

        return "General"
    def _derive_tsc_category(self, rec: dict) -> str:
        """
        Map Audit Manager control sets to SOC 2 Trust Service Categories.
        Uses either ControlSetName or the control_id prefix.
        """
        cs = (rec.get("ControlSetName") or "").lower()
        cid = (rec.get("ControlId") or "").lower()

        # Primary mapping using Audit Manager's control set name
        if "logical" in cs or "physical" in cs:
            return "Security"
        if "risk" in cs:
            return "Security"
        if "change" in cs:
            return "Security"
        if "system operations" in cs:
            return "Security"
        if "monitoring" in cs:
            return "Security"
        if "confidential" in cs:
            return "Confidentiality"
        if "availability" in cs:
            return "Availability"
        if "processing integrity" in cs or "processing" in cs:
            return "Processing Integrity"
        if "privacy" in cs:
            return "Privacy"

        # Backup mapping using the control ID prefix (C1, A1, PI1, P1, etc.)
        if cid.startswith("c1"):
            return "Confidentiality"
        if cid.startswith("a1"):
            return "Availability"
        if cid.startswith("pi1"):
            return "Processing Integrity"
        if cid.startswith("p1"):
            return "Privacy"

        # Default SOC 2 category if nothing matches
        return "Security"

    def _derive_summary_from_record(self, rec: Dict[str, Any]) -> str:
        """
        Clean, human-readable summary for the Excel 'summary' column.
        Hides raw Python errors and folds status + finding into something sane.
        """
        status = (rec.get("ComplianceStatus") or "UNKNOWN").upper()
        finding = (rec.get("Finding") or "").strip()

        # Normalize ugly internal error messages
        if "Error collecting evidence" in finding:
            return "Evidence collection error – manual review required"

        if "No evidence folders found" in finding:
            return "No recent evidence in Audit Manager"

        if status in ("FAILED", "NON_COMPLIANT"):
            if not finding:
                return "Control failed – remediation required"
            return f"FAILED – {finding[:140]}"

        if status in ("PASSED", "COMPLIANT"):
            return "Evidence OK"

        # Default: just show trimmed finding text
        return finding[:140] if finding else "No evidence text available"
     

    # -------------------------- CSV summary -------------------------- #

    def generate_csv_summary_and_store(self, evidence_records):
        """
        Write a slimmed-down CSV for RAG indexing.

        Columns:
        - framework, control_id, tsc_category, service, severity, summary, details, timestamp

        Now normalized so:
        - control_id matches your SOC2 IDs (CC6.x, CC7.x, A1.x, C1.x) whenever possible
        - framework can be read from soc2_controls.csv if present (else defaults to SOC2)
        """
        if not evidence_records:
            logger.warning("No evidence records – CSV summary will be empty placeholder.")
            evidence_records = [self._create_placeholder_record({}, {"id": "N/A", "name": "N/A"})]

        # Load your 28-control mapping once
        soc2_mapping = load_soc2_mapping()

        csv_buffer = StringIO()
        fieldnames = [
            "framework",
            "control_id",
            "tsc_category",
            "service",
            "evidence_source",
            "severity",
            "summary",
            "remediation_recommended",
            "details",
            "timestamp",
        ]
        writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
        writer.writeheader()

        for rec in evidence_records:
            # 🔧 Safety: ensure rec is always a dict
            if not isinstance(rec, dict):
                rec = {
                    "ControlSetName": "Unknown",
                    "ControlId": "UNKNOWN",
                    "ControlName": "Unknown",
                    "EvidenceDate": "N/A",
                    "EvidenceType": "Error",
                    "ComplianceStatus": "UNKNOWN",
                    "Finding": str(rec),
                    "ResourceArn": "",
                    "Severity": "LOW",
                }

            # --- SOC 2 control id (already working) ---
            soc2_id = infer_soc2_control_id(rec, soc2_mapping)

            # --- SERVICE column (Security Hub + others) ---
            evidence_type = (rec.get("EvidenceType") or "").lower()
            arn = (rec.get("ResourceArn") or "").lower()

            if "security_findings" in evidence_type or "securityhub" in evidence_type:
                service = "Security Hub"
            elif "config" in evidence_type or ":config:" in arn:
                service = "Config"
            elif "s3" in arn:
                service = "S3"
            elif "iam" in arn:
                service = "IAM"
            elif "cloudtrail" in arn:
                service = "CloudTrail"
            elif "lambda" in arn:
                service = "Lambda"
            else:
                service = "General"

            # --- EVIDENCE SOURCE column ---
            if "security_findings" in evidence_type or "securityhub" in evidence_type:
                evidence_source = "Security Hub"
            elif "config" in evidence_type or ":config:" in arn:
                evidence_source = "Config"
            elif "manual review required" in evidence_type:
                evidence_source = "Manual"
            else:
                evidence_source = "Other/Unknown"

            # --- SUMMARY column (Security Hub-aware, no raw Python errors) ---
            status = (rec.get("ComplianceStatus") or "UNKNOWN").upper()
            finding = (rec.get("Finding") or "").strip()
            finding_lower = finding.lower()

            # Security Hub specific phrasing
            if service == "Security Hub":
                if status in ("FAILED", "NON_COMPLIANT"):
                    summary = f"Security Hub FAILED – {finding[:120] or 'see findings in console'}"
                elif status in ("PASSED", "COMPLIANT"):
                    summary = "Security Hub COMPLIANT"
                else:
                    summary = f"Security Hub – {finding[:120] or 'status UNKNOWN'}"
            else:
                if "no evidence folders found" in finding_lower:
                    summary = "No recent Audit Manager evidence"
                elif "error collecting evidence" in finding_lower:
                    summary = "Evidence collection error – manual review required"
                elif status in ("FAILED", "NON_COMPLIANT"):
                    summary = f"FAILED – {finding[:120] or 'remediation required'}"
                elif status in ("PASSED", "COMPLIANT"):
                    summary = "Evidence OK"
                else:
                    summary = finding[:120] if finding else "No evidence text available"

             # --- REMEDIATION RECOMMENDED column ---
            sev = (rec.get("Severity") or "LOW").upper()
            summary_lower = summary.lower()

            if status in ("FAILED", "NON_COMPLIANT"):
                remediation_recommended = "Yes"
            elif "error collection" in summary_lower or "manual review" in summary_lower:
                remediation_recommended = "Yes"
            elif "no recent audit manager evidence" in summary_lower:
                remediation_recommended = "Review"
            elif status in ("PASSED", "COMPLIANT") and sev in ("LOW", "INFORMATIONAL"):
                remediation_recommended = "No"
            else:
                remediation_recommended = "Review"

            # --- TIMESTAMP column (hide 'No Evidence') ---
            timestamp = rec.get("EvidenceDate", "")
            if isinstance(timestamp, str) and timestamp.strip().lower() == "no evidence":
                timestamp = ""

            # Framework from mapping, default SOC2
            meta = soc2_mapping.get(soc2_id, {})
            framework = meta.get("framework", "SOC2")

            writer.writerow(
                {
                    "framework": framework,
                    "control_id": soc2_id,
                    "tsc_category": self._derive_tsc_category(rec),
                    "service": service,
                    "evidence_source": evidence_source,
                    "severity": rec.get("Severity", "LOW"),
                    "summary": summary,
                    "remediation_recommended": remediation_recommended,
                    "details": f"{rec.get('ControlName','')} in {rec.get('ControlSetName','')} – {rec.get('EvidenceType','')}",
                    "timestamp": timestamp,
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
        """.strip()

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

                # NOTE: use the global BEDROCK_CLAUDE_MODEL_ID and the self.bedrock client
                resp = self.bedrock.invoke_model(
                    modelId=BEDROCK_CLAUDE_MODEL_ID,
                    body=body,
                    contentType="application/json",
                    accept="application/json",
                )
                resp_body = json.loads(resp["body"].read())

                # Claude 3 on Bedrock: {"content":[{"type":"text","text":"..."}], ...}
                content = resp_body.get("content", [])
                text_parts = [c.get("text", "") for c in content if c.get("type") == "text"]
                text = "\n".join([t for t in text_parts if t]).strip()

                if not text:
                    raise ValueError("Empty Bedrock response")

                return text

            except Exception as e:
                logger.warning(f"Bedrock recommendations failed, using static text. Error: {e}")
                # Fallback: static bullets
                return (
                    "- **High Priority:** Review and address all FAILED controls with Critical/High severity. "
                    "Confirm ownership and open remediation tickets in your GRC backlog.\n"
                    "- **Medium Priority:** Work through remaining FAILED controls with Medium severity, "
                    "focusing on production accounts and internet-exposed resources.\n"
                    "- **Ongoing:** Maintain weekly monitoring of AWS Config, Security Hub, and Audit Manager. "
                    "Re-run this report after major changes or incidents."
                )
    def build_ai_exec_summary(self, summary: dict) -> str:
            """
            Generate a full paragraph-style executive summary for the weekly SOC 2 report
            using Claude via Bedrock. This appears ABOVE the bullet-style recommendations.
            """
            prompt = f"""
        You are a senior cloud security and GRC engineer. 
        Write a SINGLE PARAGRAPH executive summary (5–7 sentences) for a weekly SOC 2 audit report.

        Use the metrics below to describe:
        - overall security posture
        - whether compliance is improving or worsening
        - themes seen in control failures
        - business risk implications
        - what the organization should prioritize next week

        DO NOT restate the raw numbers exactly.
        DO NOT create bullet points.
        DO NOT say 'in summary' or 'overall'.  
        Write like a CISO briefing another CISO.

        Metrics:
        - Total controls evaluated: {summary['total_controls']}
        - Passed: {summary['passed_controls']}
        - Failed: {summary['failed_controls']}
        - Unknown: {summary['unknown_controls']}
        - Compliance rate: {summary['compliance_rate']:.1f}%
        - Critical/High failures: {summary['critical_high']}
        - Medium failures: {summary['medium']}
        """

            try:
                body = json.dumps({
                    "messages": [
                        {
                            "role": "user",
                            "content": [{"type": "text", "text": prompt}],
                        }
                    ],
                    "max_tokens": 400,
                    "temperature": 0.3,
                })

                resp = self.bedrock.invoke_model(
                    modelId=self.bedrock_model_id,
                    body=body,
                )
                resp_body = json.loads(resp["body"].read())

                content = resp_body["output"]["message"]["content"]
                text_parts = [c["text"] for c in content if c.get("type") == "text"]
                paragraph = " ".join(text_parts).strip()

                if not paragraph:
                    raise ValueError("Claude returned empty executive summary.")

                return paragraph

            except Exception as e:
                logger.warning(f"AI exec summary failed, using fallback. Error: {e}")
                return (
                    "This week's compliance posture shows notable areas requiring attention. "
                    "Control failures indicate opportunities to strengthen IAM, logging, and "
                    "configuration management processes, while medium-severity issues highlight "
                    "gaps that should be scheduled for review next week. Continue focusing on "
                    "closing findings tied directly to customer-impacting risks and maintaining "
                    "strong evidence collection for audit readiness."
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
            ai_exec_summary = self.build_ai_exec_summary(summary)
            ai_recommendations = self.build_ai_recommendations(summary)

            body = f"""Weekly SOC 2 Audit Summary – {today}

    # Weekly SOC 2 Audit Summary

    ## AI Executive Summary
    {ai_exec_summary}

    ## Key Recommendations

    {ai_recommendations}

    ## Next Steps

    Download the detailed CSV evidence summary:
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




