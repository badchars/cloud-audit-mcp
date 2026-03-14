# Industry Standards & Compliance Frameworks

> Sources: CIS Benchmarks, NIST 800-53 Rev5, CSA CCM v4, OWASP Cloud Top 10, Azure Security Benchmark v3, MITRE ATT&CK Cloud

## 1. CIS Foundations Benchmarks

### AWS Foundations Benchmark (v3.0 / v6.0)

| Section | Title | Key Controls |
|---------|-------|-------------|
| 1 | IAM | 1.4 Root MFA, 1.5 Root no access keys, 1.8 Password policy length, 1.10 MFA for console, 1.12 No unused creds >45d, 1.14 Access key rotation ≤90d, 1.16 No inline policies, 1.17 IAM Access Analyzer |
| 2 | Storage | 2.1.1 S3 deny HTTP, 2.1.2 S3 MFA Delete, 2.1.4 S3 Block Public Access, 2.1.5 S3 SSE, 2.3.1 RDS encryption, 2.3.2 RDS auto-upgrade, 2.4.1 EFS encryption |
| 3 | Logging | 3.1 CloudTrail all regions, 3.2 CloudTrail log validation, 3.3 S3 bucket not public (logs), 3.4 CloudTrail + CloudWatch, 3.6 S3 access logging, 3.7 KMS CMK rotation, 3.9 VPC flow logs |
| 4 | Monitoring | 4.1-4.15 CloudWatch log metric filters (unauthorized API, root usage, IAM changes, CloudTrail changes, S3 policy, Config changes, SG changes, NACL, IGW, Route table, VPC changes, Organizations changes) |
| 5 | Networking | 5.1 No 0.0.0.0/0 SSH, 5.2 No 0.0.0.0/0 RDP, 5.3 No 0.0.0.0/0 to remote admin ports, 5.4 Default SG restricts all, 5.6 EC2 metadata IMDSv2 |

### Azure Foundations Benchmark (v2.1 / v5.0)

| Section | Title | Key Controls |
|---------|-------|-------------|
| 1 | IAM | 1.1 Security defaults, 1.2 MFA for privileged, 1.3 MFA for all, 1.5 No guest users, 1.21 No custom subscription owner roles |
| 2 | Defender | 2.1 Defender for servers, 2.2 Defender for App Services, 2.3 Defender for SQL, 2.4 Defender for storage, 2.5 Defender for K8s, 2.6 Defender for Key Vault |
| 3 | Storage | 3.1 Secure transfer (HTTPS), 3.2 No anonymous blob, 3.3 Regenerate keys, 3.7 SAS expiry ≤1hr, 3.8 CMK encryption, 3.9 Soft delete, 3.15 Private endpoints |
| 4 | SQL | 4.1 Auditing on, 4.2 Threat detection, 4.3 Retention ≥90d, 4.4 Azure AD admin, 4.5 TDE with CMK |
| 5 | Logging | 5.1 Diagnostic settings all resources, 5.2 Activity Log retention, 5.3 Log alert for policy/NSG/SG |
| 6 | Networking | 6.1 No RDP 0.0.0.0/0, 6.2 No SSH 0.0.0.0/0, 6.3 No UDP 0.0.0.0/0, 6.5 Network Watcher, 6.6 NSG flow logs |
| 7 | VMs | 7.1 Managed disks, 7.2 OS disk CMK, 7.4 Unattached disk CMK, 7.5 Trusted launch, 7.7 Endpoint protection |
| 8 | Key Vault | 8.1 Key expiry, 8.2 Secret expiry, 8.3 RBAC, 8.4 Private endpoint, 8.5 Key rotation, 8.7 Purge protection |
| 9 | App Service | 9.1 App Service auth, 9.2 HTTPS redirect, 9.3 TLS 1.2, 9.4 Register with AAD, 9.5 Latest runtime, 9.10 FTP disabled |

### GCP Foundations Benchmark (v2.0 / v4.0)

| Section | Title | Key Controls |
|---------|-------|-------------|
| 1 | IAM | 1.1 No SA admin, 1.3 No SA user-managed keys, 1.4 No SA key older than 90d, 1.5 Separation of duties, 1.6 KMS separation, 1.7 API keys restricted, 1.8 API key rotation, 1.10 KMS CMK for SA |
| 2 | Logging | 2.1 Cloud Audit Logging enabled, 2.2 Log sinks configured, 2.3 Retention ≥400d, 2.4-2.12 Log metric filters (project ownership, audit config, custom role, VPC firewall, route, VPC network, storage IAM, SQL config, Cloud Functions) |
| 3 | Networking | 3.1 No default network, 3.2 Legacy networks prohibited, 3.3 DNSSEC enabled, 3.4 No RSASHA1 DNSSEC, 3.6 No SSH 0.0.0.0/0, 3.7 No RDP 0.0.0.0/0, 3.8 VPC flow logs, 3.9 No default SA for instances, 3.10 Private Google Access |
| 4 | VMs | 4.1 No default SA, 4.2 No full API scope, 4.3 OS Login enabled, 4.4 No project-wide SSH keys, 4.5 Serial port disabled, 4.6 Shielded VM, 4.8 Confidential Computing, 4.11 No public IP |
| 5 | Storage | 5.1 No public GCS, 5.2 Uniform bucket-level access |
| 6 | Cloud SQL | 6.1 No public IP (MySQL), 6.2 SSL required, 6.3 No authorized networks 0.0.0.0/0, 6.5 DB flags (log_connections, log_disconnections for Postgres), 6.7 No contained database auth (SQL Server) |
| 7 | BigQuery | 7.1 CMK encryption, 7.2 No public dataset, 7.3 Access transparency |

### CIS Kubernetes Benchmark (v1.12.0)

| Section | Key Controls |
|---------|-------------|
| 1. Control Plane | API server auth, RBAC enabled, audit logging, encryption provider, strong ciphers |
| 2. etcd | Cert auth, peer certs, no auto-TLS |
| 3. Control Plane Config | No client cert auth for users, minimal audit policy |
| 4. Worker Nodes | Kubelet auth, no anonymous auth, cert rotation, seccomp |
| 5. Policies | Cluster-admin limited, minimize secrets access, no wildcards in RBAC, PSS enforced, NetworkPolicies, image provenance |

---

## 2. NIST 800-53 Rev 5 (Cloud-Relevant)

| Family | Controls | Cloud-Audit Checks |
|--------|----------|-------------------|
| **AC** Access Control | AC-2 Account Mgmt, AC-3 Access Enforcement, AC-5 Separation of Duties, AC-6 Least Privilege, AC-17 Remote Access | Unused accounts, over-permissive policies, admin separation, MFA for remote |
| **IA** Identification & Auth | IA-2 MFA, IA-5 Credential Mgmt, IA-8 External Auth | MFA enforcement, key rotation, federation trust |
| **SC** System & Comms | SC-7 Boundary Protection, SC-8 Transmission Confidentiality, SC-12 Crypto Key Mgmt, SC-28 Data at Rest | SG/NSG rules, TLS enforcement, KMS rotation, encryption verification |
| **AU** Audit | AU-2 Event Logging, AU-3 Audit Content, AU-6 Audit Review, AU-9 Audit Protection, AU-11 Retention | CloudTrail/Activity Log enabled, log integrity, immutable logging, retention |
| **CM** Config Mgmt | CM-2 Baseline Config, CM-6 Config Settings, CM-8 Inventory | Config drift, security settings, asset inventory |
| **SA** Supply Chain | SA-12 Supply Chain Protection | Container image provenance, IaC module integrity |

---

## 3. CSA Cloud Controls Matrix v4.1

| Domain | ID | Key Controls for Automation |
|--------|----|-----------------------------|
| IAM | IAM-01..16 | MFA, privilege separation, SA key rotation, cross-account trust |
| IVS | IVS-01..13 | Network segmentation, firewall rules, VPC isolation |
| LOG | LOG-01..15 | Audit logging all services, log integrity, retention |
| CEK | CEK-01..21 | Encryption at rest/transit, key rotation, HSM usage |
| DSP | DSP-01..19 | Data classification, access controls, privacy |
| TVM | TVM-01..10 | Vulnerability scanning, patch management, pen testing |
| STA | STA-01..14 | Supply chain review, third-party risk |

---

## 4. OWASP Cloud Top 10 (2025)

| # | Risk | Automated Check Categories |
|---|------|---------------------------|
| 1 | Insecure Cloud Configuration | Default configs, open storage, permissive firewall, debug modes |
| 2 | Insecure Secrets Management | Hardcoded keys in Lambda/Docker/DSC, unencrypted param store |
| 3 | Insecure Software Supply Chain | Unverified images, dependency confusion, unsigned IaC |
| 4 | Broken Authentication | Default creds, SAML/OIDC misconfig, missing MFA, weak passwords |
| 5 | Overly Permissive Access | Wildcard IAM, unused permissions, cross-account over-trust |
| 6 | Security Observability Failures | Missing CloudTrail, no centralized logging, no real-time alerting |
| 7 | Improper Isolation | Container breakout paths, shared VPC risks, namespace isolation |
| 8 | Insecure APIs | Missing API auth, no rate limiting, exposed management endpoints |
| 9 | Lack of Policy Enforcement | No SCP/guardrails, shadow IT, no tagging policies |
| 10 | Insufficient Incident Response | No playbooks, no automated containment, no forensic readiness |

---

## 5. Azure Security Benchmark v3

| Family | Key Checks |
|--------|-----------|
| NS Network Security | VNet segmentation, NSG rules, private endpoints, DDoS protection |
| IM Identity Mgmt | Azure AD centralized, SSO, MFA, managed identities, conditional access |
| PA Privileged Access | PIM (just-in-time), PAW, admin separation |
| DP Data Protection | TLS 1.2+, encryption at rest (CMEK), data classification |
| LT Logging & Detection | Defender, Sentinel, centralized logs, retention |
| PV Posture & Vuln Mgmt | Vulnerability scanning, config tracking, remediation SLAs |
| DS DevOps Security | Static analysis, IaC scanning, supply chain security |

---

## 6. MITRE ATT&CK Cloud Matrix

### Key Tactics & Detection Checks

| Tactic | Cloud Techniques | Detection |
|--------|-----------------|-----------|
| **Initial Access** | Valid Accounts: Cloud, Trusted Relationship, Exploit Public App | Impossible travel, unusual API calls, OAuth app consents |
| **Execution** | Cloud Admin Command (SSM/RunCommand), Serverless Execution | Monitor RunCommand, Lambda creation by unauthorized principals |
| **Persistence** | Account Manipulation (new users/keys), Create Account, Implant Internal Image | New IAM keys, federation changes, AMI/image integrity |
| **Privilege Escalation** | Abuse Elevation (PassRole/AssumeRole), Domain Policy Modification | PassRole abuse, SCP changes |
| **Defense Evasion** | Impair Defenses (disable CloudTrail/GuardDuty), Unused Regions, Alt Auth Material | Logging config changes, resources in unmonitored regions, stolen tokens |
| **Credential Access** | Unsecured Credentials (IMDS, env vars), Forge SAML Tokens, Steal App Tokens | IMDSv1, golden SAML, OAuth token theft |
| **Discovery** | Cloud Infrastructure Discovery, Storage Object Discovery | API enumeration anomalies |
| **Lateral Movement** | Alt Auth Material (STS/refresh tokens), Remote Cloud Services | Token reuse, SSM sessions |
| **Exfiltration** | Data from Cloud Storage, Transfer to External Account | Cross-account replication, snapshot sharing |
| **Impact** | Resource Hijacking (cryptomining), Data Encrypted for Impact | Unusual instance types, billing anomalies |

---

## 7. Checks NOT in Our HTB Knowledge Base (Gaps to Fill)

Based on CIS/NIST/Prowler/MITRE, these checks are missing from our current HTB-derived knowledge:

### AWS Gaps
- CloudTrail multi-region + log validation + KMS encryption
- CloudWatch log metric filters (14 specific alarm patterns from CIS 4.x)
- GuardDuty enabled in all regions
- AWS Config enabled with required rules
- RDS public access + encryption + IAM auth
- Root account MFA + no access keys
- Password policy enforcement
- VPC flow logs on all VPCs
- Default SG restricts all traffic
- KMS CMK rotation enabled
- Access key rotation ≤90 days
- Unused credentials >45 days
- IAM Access Analyzer enabled
- Bedrock guardrails (prompt injection)
- CloudFront HTTPS/WAF
- S3 MFA Delete
- Organizations SCP audit
- Unused region resource detection (MITRE T1535)
- Cross-account role trust audit (confused deputy)

### Azure Gaps
- Defender for Cloud all plans enabled
- Diagnostic settings on all resources
- Activity Log alerts (policy/NSG/SG changes)
- Key Vault expiry + rotation + purge protection
- TLS 1.2 enforcement on App Service
- FTP disabled on App Service
- Network Watcher enabled
- NSG flow logs
- PIM (Privileged Identity Management) enforced
- Conditional Access policies
- Trusted Launch on VMs
- Private endpoints for PaaS services

### GCP Gaps
- Cloud Audit Logging (Data Access opt-in)
- Log metric filters (10 specific from CIS 2.x)
- No default network
- OS Login enabled
- Serial port disabled
- Shielded VM / Confidential Computing
- No project-wide SSH keys
- Cloud SQL DB flags (log_connections, pgaudit)
- BigQuery public dataset check
- VPC Service Controls
- Binary Authorization for GKE
- Organization policy constraints

### Cross-Cloud Gaps
- Data exfiltration path detection (replication, snapshot sharing)
- Supply chain integrity (container signing, IaC modules)
- Cryptomining detection (unusual instance types, billing)
- Logging integrity (tamper protection)
- Incident response readiness (playbooks, forensic env)
