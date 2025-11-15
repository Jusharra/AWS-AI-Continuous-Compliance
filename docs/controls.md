# FAFO Continuous Compliance – Control Mapping

## 9.2 Turning Controls Into Cloud Signals

A guided enablement plan—and why each AWS “switch” exists.

---

### 9.2.1 Why Amazon Built These Standards in the First Place

| AWS Feature                              | What it is                                                                      | Why Amazon created it                                                                                                  | How auditors view it                                                                                     |
|-----------------------------------------|----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| AWS Security Hub – Standards tab        | A catalogue of ready-made security controls, each expressed in ASFF.            | To give every customer an opinionated baseline—no need to invent your own S3-encryption check or IAM-MFA rule.        | “Independent” automated proof that a control runs continuously, backed by AWS-signed log data.          |
| Foundational Security Best Practices    | Amazon-curated controls that apply to every AWS account.                        | Customers begged for a single superset that maps to CIS, NIST, and ISO without doing overlap diffing manually.        | Evidence that your cloud matches what AWS itself calls foundational.                                     |
| CIS AWS Foundations Benchmark           | Community standard co-written by AWS, Google, Microsoft & the open-source orgs. | To provide a vendor-neutral baseline; many regulators explicitly reference CIS.                                        | A known-good “north-star.” Complying with CIS satisfies large chunks of SOC 2, ISO 27001, PCI, etc.     |
| AWS Config Conformance Pack             | CloudFormation bundle that deploys many managed Config rules in one shot.       | To turn CIS/FSBP guidance into always-on drift detection with time-series resource state history.                     | Continuous, timestamped pass/fail evidence that maps cleanly to “control operating effectiveness.”       |

**Key point**

- **Security Hub** tells you when a control fails (snapshot).
- **AWS Config** proves how long it stayed failed or compliant (history).

Together they give auditors both the **snapshot** and the **timeline**.

---

### 9.2.2 Choosing—and Tuning—the Baselines

1. **Enable, then prune**

   - FSBP & CIS each ship with hundreds of controls. Turn them all on without triage and you drown in noise.
   - Strategy for FAFO:
     1. Enable both standards in a staging OU.
     2. Run for two weeks.
     3. Mark every finding as either **Legitimate Gap** or **Business-Accepted Risk**.
     4. Disable controls that are permanently N/A (for example, EKS controls if FAFO doesn’t run Kubernetes).

2. **Use Config packs only for rules you plan to enforce**

   - Managed rules cost money; over-enabling is wasteful.
   - Deploy CIS 1.4 and KMS Operational Best Practices only in production and security accounts.
   - Keep dev accounts lighter to reduce noise and cost.

3. **Document every disabled control in Audit Manager**

   - Auditors will ask “Why is ELB.5 disabled?”
   - FAFO answer example:  
     > Company does not use classic ELB; all load balancers are ALB/NLB. Control disabled to prevent false positives.
   - Store those justifications as “Management Responses” in the SOC 2 assessment.

---

### 9.2.3 Revised Mapping of 28 Automatable Controls

Below we map each SOC 2 criterion to the specific AWS-managed control. Controls outside FSBP/CIS are omitted on purpose; we want **zero custom rules** for this lab.

| SOC 2 Ref      | Condensed Description              | AWS Check                                  | Standard   | Status in FAFO |
|----------------|------------------------------------|--------------------------------------------|-----------|----------------|
| CC 6.1.2       | MFA enforced                       | IAM.5 / IAM.6                              | FSBP      | Enabled        |
| CC 6.1.3       | Strong password policy             | IAM.1 / IAM.2                              | FSBP      | Enabled        |
| CC 6.1.4       | Inbound ports restricted           | vpc-sg-open-only-to-authorized-ports       | CIS Pack  | Enabled        |
| CC 6.1.6       | TLS everywhere                     | ELB.1 / CloudFront.1                       | FSBP      | Enabled        |
| CC 6.1.7       | DB encryption                      | RDS.1                                      | FSBP      | Enabled        |
| CC 6.1.8       | Key rotation                       | kms-key-rotation-enabled                   | KMS Pack  | Enabled        |
| CC 6.1.9       | RBAC via groups                    | IAM.3                                      | FSBP      | Enabled        |
| CC 6.1.10      | Data-at-rest encryption            | S3.2 / EBS.1 / RDS.3                       | FSBP      | Enabled        |
| CC 6.2.1       | Admin access limited               | IAM.4                                      | FSBP      | Enabled        |
| CC 6.6.2       | Security monitoring active         | GuardDuty                                  | FSBP      | Enabled        |
| CC 6.6.3       | IDS / IPS                          | GuardDuty + VPC.1                          | FSBP      | Enabled        |
| CC 6.6.4       | Log aggregation (SIEM)             | CloudTrail.2 / CloudWatch.5                | FSBP      | Enabled        |
| CC 7.2 – Scan  | Monthly vuln scans (static)        | Git → ASFF (SAST findings)                 | GitLab    | Enabled        |
| CC 7.2 – DAST  | Dynamic app scans                  | Git → ASFF (DAST findings)                 | GitLab    | Enabled        |
| CC 7.2 – Cont. | Container image scans              | ECR.1                                      | FSBP      | Enabled        |
| CC 8.1.3       | Version control with RBAC          | Git evidence (branch protection, reviews)  | GitLab    | Enabled        |
| CC 8.1.5       | Static code scan                   | Git → ASFF (SAST)                          | GitLab    | Enabled        |
| CC 8.1.7       | Approved change                    | CodePipeline / Git MR approvals            | Internal  | Enabled        |
| CC 8.1.9       | Deploy alerts                      | CloudWatch.14                              | CIS       | Enabled        |
| CC 9.1.3       | Cross-AZ backups                   | rds-automatic-backup-enabled               | CIS       | Enabled        |
| A 1.1.1        | Capacity monitoring                | EC2.8 + CloudWatch alarms                  | FSBP      | Enabled        |
| A 1.1.2        | Auto-scaling                       | autoscaling-group-elb-healthcheck-required | CIS       | Enabled        |
| A 1.2.1        | Backup failure alerts              | Backup.1                                   | FSBP      | Enabled        |
| A 1.2.3        | Multi-AZ architecture              | rds-multi-az-support                       | CIS       | Enabled        |
| C 1.1.3        | Data inventory review              | Manual                                     | –         | Out of scope   |
| CC 6.7.1       | Data-loss prevention               | Manual                                     | –         | Out of scope   |
| A1.2.4/5/6     | Physical / BMS controls            | Manual                                     | –         | Out of scope   |

**Noise reduction**

- Controls like `ELB.3` (classic ELB logging) and `EKS.2` (EKS control plane logging) exist in FSBP but FAFO does not use those services.
- We disable them to keep Security Hub scores meaningful.

---

### 9.2.4 Collaborating With Security Ops

- **Kick-off meeting (30 min)**  
  Walk through the mapping table, disabled controls, and expectations.
- **Slack / Teams channel (e.g., `#soc2-signals`)**  
  Critical findings from Security Hub / Config post here. SecOps triages; GRC observes.
- **Monthly architecture review**  
  If FAFO adopts a new AWS service, revisit which controls to enable.

**Outcome:**  
Security owns alert response. GRC owns evidence curation.  
No one feels blindsided during audit season.
