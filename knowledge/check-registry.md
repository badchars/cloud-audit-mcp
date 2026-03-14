# Cloud Audit MCP — Check Registry

> Master list of all checks from HTB assessments + CIS Benchmarks + Prowler + NIST 800-53 + MITRE ATT&CK + Rhino Security Labs.
> Total: 53 HTB vulns + 40 industry-standard checks → 100+ automated checks.

## Priority Matrix

### P0 — CRITICAL (Must ship in v1)

| ID | Cloud | Check | Source |
|----|-------|-------|--------|
| S3-001 | AWS | Public bucket access (ACL + policy + Block Public Access) | HailStorm |
| S3-002 | AWS | Sensitive objects in S3 (SSH keys, SQL dumps, source code) | HailStorm |
| IAM-001 | AWS | Policy version privilege escalation | HailStorm |
| IAM-002 | AWS | Dangerous permission combos (PassRole+CreateFunction, etc.) | HailStorm |
| EC2-001 | AWS | IMDSv1 enabled | HailStorm |
| EC2-002 | AWS | Unencrypted/accessible EBS snapshots | HailStorm |
| LAMBDA-001 | AWS | Secrets in Lambda environment variables | HailStorm |
| LAMBDA-002 | AWS | UpdateFunctionCode permission | HailStorm |
| ECR-001 | AWS | Hardcoded credentials in Docker images | HailStorm |
| STOR-001 | Azure | Public blob access enabled | Cyclone |
| STOR-002 | Azure | Container public access level | Cyclone |
| AUTO-002 | Azure | DSC configuration plaintext passwords | Cyclone |
| VM-001 | Azure | Management ports exposed (WinRM/RDP/SSH) | Cyclone |
| VM-004 | Azure | Over-privileged managed identities | Cyclone |
| LOGIC-001 | Azure | SSRF via managed identity | Cyclone |
| FUNC-001 | Azure | Anonymous auth level on functions | Cyclone |
| GCS-001 | GCP | Public bucket access (allUsers/allAuthenticatedUsers) | Blizzard |
| GCS-002 | GCP | SA keys in storage buckets | Blizzard |
| META-001 | GCP | Startup script secrets | Blizzard |
| META-002 | GCP | Instance with cloud-platform scope | Blizzard |
| IAM-002g | GCP | Delegation chain detection | Blizzard |
| IAM-004g | GCP | setMetadata permission (SSH key injection) | Blizzard |
| K8S-001 | GCP | Default SA with cluster-admin | Blizzard |
| K8S-002 | GCP | Privileged containers allowed | Blizzard |

### P1 — HIGH (Ship in v1.1)

| ID | Cloud | Check | Source |
|----|-------|-------|--------|
| IAM-003 | AWS | Lambda execution roles with admin access | HailStorm |
| IAM-004 | AWS | Git repository credential exposure | HailStorm |
| EC2-003 | AWS | Security groups with 0.0.0.0/0 | HailStorm |
| LAMBDA-003 | AWS | Event source mapping as invocation bypass | HailStorm |
| SM-001 | AWS | Over-permissive secret access | HailStorm |
| DYNAMO-001 | AWS | Cleartext credentials in DynamoDB tables | HailStorm |
| DYNAMO-002 | AWS | DynamoDB streams to Lambda chains | HailStorm |
| APIGW-001 | AWS | API without authentication | HailStorm |
| SAGE-001 | AWS | SageMaker notebook instance access | HailStorm |
| STOR-003 | Azure | Long-lived SAS tokens | Cyclone |
| STOR-004 | Azure | Cloud Shell storage exposure | Cyclone |
| AUTO-001 | Azure | Hardcoded credentials in runbooks | Cyclone |
| VM-002 | Azure | Unencrypted VM disks | Cyclone |
| VM-003 | Azure | Password reuse across VMs | Cyclone |
| VM-005 | Azure | IMDS token theft exposure | Cyclone |
| AAD-002 | Azure | User consent settings (OAuth phishing) | Cyclone |
| AAD-003 | Azure | PRT theft risk (no Credential Guard) | Cyclone |
| ACR-001 | Azure | Admin user enabled | Cyclone |
| ACR-002 | Azure | Secrets in container images | Cyclone |
| SQL-001 | Azure | SQL authentication enabled | Cyclone |
| SQL-002 | Azure | Overly permissive firewall rules | Cyclone |
| WEBAPP-002 | Azure | Connection strings with credentials | Cyclone |
| GCS-003 | GCP | Sensitive files in buckets | Blizzard |
| IAM-001g | GCP | Service account key audit | Blizzard |
| IAM-003g | GCP | Token Creator role abuse | Blizzard |
| META-003 | GCP | Metadata concealment not enabled | Blizzard |
| K8S-003 | GCP | Kubelet API exposure | Blizzard |
| GCR-001 | GCP | Unexpected/hidden images in GCR | Blizzard |

### P2 — MEDIUM (v1.2+)

| ID | Cloud | Check | Source |
|----|-------|-------|--------|
| S3-003 | AWS | Bucket name leaks account ID | HailStorm |
| ECR-002 | AWS | Sensitive files in image layers | HailStorm |
| AAD-001 | Azure | Secrets in AD object descriptions | Cyclone |
| AUTO-003 | Azure | Automation variables unencrypted | Cyclone |
| KV-001 | Azure | Overly permissive Key Vault access | Cyclone |
| KV-002 | Azure | Key Vault network access not restricted | Cyclone |
| WEBAPP-001 | Azure | SCM basic auth enabled | Cyclone |
| WEBAPP-003 | Azure | Deployment packages in accessible storage | Cyclone |
| FUNC-002 | Azure | User input passed to Key Vault | Cyclone |
| K8S-004 | GCP | SA token automount | Blizzard |

---

## Check → MCP Tool Mapping

Each check maps to one or more MCP tools that the agent will call:

### AWS Tools
```
aws_check_s3_public        → S3-001
aws_check_s3_objects        → S3-002, S3-003
aws_check_iam_policies      → IAM-001, IAM-002, IAM-003
aws_check_ec2_imds          → EC2-001
aws_check_ec2_snapshots     → EC2-002
aws_check_ec2_security_groups → EC2-003
aws_check_lambda_env        → LAMBDA-001
aws_check_lambda_permissions → LAMBDA-002, LAMBDA-003
aws_check_ecr_images        → ECR-001, ECR-002
aws_check_secrets_manager   → SM-001
aws_check_dynamodb          → DYNAMO-001, DYNAMO-002
aws_check_api_gateway       → APIGW-001
aws_check_sagemaker         → SAGE-001
```

### Azure Tools
```
azure_check_storage_public   → STOR-001, STOR-002
azure_check_storage_sas      → STOR-003
azure_check_automation       → AUTO-001, AUTO-002, AUTO-003
azure_check_vm_network       → VM-001
azure_check_vm_encryption    → VM-002
azure_check_vm_identity      → VM-004, VM-005
azure_check_ad_consent       → AAD-001, AAD-002
azure_check_logic_apps       → LOGIC-001
azure_check_functions        → FUNC-001, FUNC-002
azure_check_keyvault         → KV-001, KV-002
azure_check_acr              → ACR-001, ACR-002
azure_check_sql              → SQL-001, SQL-002
azure_check_webapp           → WEBAPP-001, WEBAPP-002, WEBAPP-003
```

### GCP Tools
```
gcp_check_gcs_public        → GCS-001
gcp_check_gcs_objects        → GCS-002, GCS-003
gcp_check_metadata           → META-001, META-002, META-003
gcp_check_iam_keys           → IAM-001g
gcp_check_iam_delegation     → IAM-002g, IAM-003g
gcp_check_iam_compute        → IAM-004g
gcp_check_kubernetes         → K8S-001, K8S-002, K8S-003, K8S-004
gcp_check_gcr                → GCR-001
```

---

## Severity Distribution

```
CRITICAL:  24 checks (45%)  ← Real exploitable issues
HIGH:      28 checks (53%)  ← Significant risk
MEDIUM:    10 checks (19%)  ← Defense-in-depth
LOW:        3 checks ( 6%)  ← Informational
```

## Cloud Distribution

```
AWS:    23 HTB + 19 CIS/Prowler = 42 checks
Azure:  22 HTB + 12 CIS/ASB    = 34 checks
GCP:    17 HTB + 12 CIS/Prowler = 29 checks
Cross:   3 HTB + 5 MITRE        =  8 patterns
```

---

## NEW: Industry-Standard Checks (from CIS/Prowler/NIST/MITRE)

### P0 — CRITICAL (Add to v1)

| ID | Cloud | Check | Source |
|----|-------|-------|--------|
| CT-001 | AWS | CloudTrail enabled all regions + log validation | CIS 3.1-3.2 |
| GD-001 | AWS | GuardDuty enabled all regions | CIS / Prowler |
| ROOT-001 | AWS | Root account MFA enabled + no access keys | CIS 1.4-1.5 |
| RDS-001 | AWS | RDS not publicly accessible | CIS 2.3 / Prowler |
| DEF-001 | Azure | Defender for Cloud all plans enabled | CIS 2.x / ASB |
| DIAG-001 | Azure | Diagnostic settings on all resources | ASB LT-1 |
| PIM-001 | Azure | No permanent Global Admin (PIM enforced) | ASB PA-1 |
| AUDIT-001 | GCP | Cloud Audit Logging (Data Access enabled) | CIS 2.1 |
| OSLOGIN-001 | GCP | OS Login enabled (no metadata SSH keys) | CIS 4.3 |
| SHIELDED-001 | GCP | Shielded VM enabled | CIS 4.6 |

### P1 — HIGH (Add to v1.1)

| ID | Cloud | Check | Source |
|----|-------|-------|--------|
| CW-001 | AWS | CloudWatch log metric filters (14 CIS alarms) | CIS 4.1-4.15 |
| VPC-001 | AWS | VPC flow logs enabled | CIS 3.9 |
| SG-002 | AWS | Default SG restricts all traffic | CIS 5.4 |
| KMS-001 | AWS | KMS CMK rotation enabled | CIS 3.7 |
| KEY-001 | AWS | Access key rotation ≤90 days | CIS 1.14 |
| UNUSED-001 | AWS | Unused credentials >45 days removed | CIS 1.12 |
| CONFIG-001 | AWS | AWS Config enabled | Prowler |
| PRIVESC-001 | AWS | IAM privilege escalation path detection (21 methods) | Rhino |
| XACCT-001 | AWS | Cross-account trust audit (confused deputy) | Rhino/MITRE |
| TLS-001 | Azure | TLS 1.2 enforcement on App Service | CIS 9.3 |
| FTP-001 | Azure | FTP disabled on App Service | CIS 9.10 |
| COND-001 | Azure | Conditional Access policies configured | ASB IM |
| NWATCHER-001 | Azure | Network Watcher enabled | CIS 6.5 |
| FLOW-001 | Azure | NSG flow logs enabled | CIS 6.6 |
| PRIV-001 | Azure | Private endpoints for PaaS services | ASB NS-2 |
| LOGMET-001 | GCP | Log metric filters (10 CIS patterns) | CIS 2.4-2.12 |
| NODEFAULT-001 | GCP | No default network | CIS 3.1 |
| SERIALPORT-001 | GCP | Serial port disabled | CIS 4.5 |
| SQLFLAGS-001 | GCP | Cloud SQL DB flags (log_connections, pgaudit) | CIS 6.5 |
| VPCSC-001 | GCP | VPC Service Controls configured | Prowler |

### P2 — MEDIUM (v1.2+)

| ID | Cloud | Check | Source |
|----|-------|-------|--------|
| BEDROCK-001 | AWS | Bedrock guardrails prompt attack filter | Prowler |
| SHADOW-001 | AWS | Shadow resource detection (predictable bucket names) | Prowler |
| DANGLING-001 | AWS | Dangling IP subdomain takeover | Prowler |
| REGION-001 | AWS | Resources in unused/unmonitored regions | MITRE T1535 |
| PASSROT-001 | AWS | Password policy enforcement | CIS 1.8 |
| ANALYZER-001 | AWS | IAM Access Analyzer enabled | CIS 1.17 |
| KVEXPIRY-001 | Azure | Key Vault key/secret expiry set | CIS 8.1-8.2 |
| KVPURGE-001 | Azure | Key Vault purge protection enabled | CIS 8.7 |
| TRUSTEDLAUNCH-001 | Azure | Trusted Launch on VMs | CIS 7.5 |
| BQPUBLIC-001 | GCP | BigQuery no public datasets | CIS 7.2 |
| BINAUTH-001 | GCP | Binary Authorization for GKE | Prowler |
| ORGPOLICY-001 | GCP | Organization policy constraints | Prowler |

---

## Knowledge Files Index

| File | Content | Lines |
|------|---------|-------|
| `aws-checks.md` | 10 categories, 23 checks from HTB HailStorm | 316 |
| `azure-checks.md` | 11 categories, 22 checks from HTB Cyclone | 373 |
| `gcp-checks.md` | 7 categories, 17 checks from HTB Blizzard | 341 |
| `attack-patterns.md` | 8 cross-cloud attack patterns | 195 |
| `industry-standards.md` | CIS, NIST 800-53, CSA CCM, OWASP, ASB, MITRE ATT&CK | 200+ |
| `privesc-paths.md` | AWS 21+, GCP 17, Azure 10 privilege escalation methods | 160+ |
| `tools-comparison.md` | Prowler, ScoutSuite, CloudSploit, Trivy, Steampipe, Pacu | 150+ |
| `check-registry.md` | This file — master priority matrix + tool mapping | 250+ |
