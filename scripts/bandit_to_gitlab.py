#!/usr/bin/env python3
"""
Convert Bandit JSON output to a GitLab-style SAST report (gl-sast-report.json)
and create a placeholder DAST report (gl-dast-report.json).

This keeps the GitLab -> Security Hub ASFF importer happy while we wire in
real DAST later.
"""

import json
from pathlib import Path


def main():
    bandit_path = Path("bandit-report.json")

    if not bandit_path.exists() or not bandit_path.read_text().strip():
        data = {"vulnerabilities": []}
    else:
        raw = json.loads(bandit_path.read_text())
        vulns = []

        for issue in raw.get("results", []):
            vulns.append(
                {
                    "id": issue.get("test_id"),
                    "name": issue.get("test_name"),
                    "description": issue.get("issue_text"),
                    "severity": issue.get("issue_severity", "Info").title(),
                    "location": {
                        "file": issue.get("filename"),
                        "line": issue.get("line_number"),
                    },
                    "solution": issue.get("test_id"),
                }
            )

        data = {"vulnerabilities": vulns}

    # Write SAST report in the format gitlab_to_asff.py expects
    Path("gl-sast-report.json").write_text(json.dumps(data))

    # DAST placeholder – will be replaced by real ZAP later
    Path("gl-dast-report.json").write_text(
        json.dumps({"vulnerabilities": []})
    )

    print(f"[INFO] Wrote gl-sast-report.json with {len(data['vulnerabilities'])} vulns")
    print("[INFO] Wrote placeholder gl-dast-report.json")


if __name__ == "__main__":
    main()
