# Cloud Security Tools Comparison

> Prowler, ScoutSuite, CloudSploit, Trivy, Steampipe, Pacu — what they check and how cloud-audit-mcp differs

## Prowler (Most Comprehensive)

- **Checks:** AWS 581, Azure 166, GCP 100, K8s 83, + 10 more providers
- **Total:** 1,200+ checks across 16 providers
- **Compliance:** 41 frameworks (CIS v1.4-v6.0, NIST 800-53 r4/r5, PCI-DSS, HIPAA, GDPR, SOC2, ISO 27001, MITRE ATT&CK, CSA CCM v4)
- **Unique Features:**
  - LLM Jacking detection (CloudTrail + APIM anomaly analysis)
  - Privilege escalation behavioral detection
  - Shadow resource vulnerability (predictable S3 naming → takeover)
  - Shodan integration (cross-reference public IPs)
  - Dangling IP subdomain takeover (Route53)
  - Attack path visualization (Neo4j + Cartography)
  - Automated remediation (`_fixer.py` per check)
  - ThreatScore (weighted risk prioritization)
  - 17 check categories (internet-exposed, secrets, threat-detection, gen-ai, etc.)

### Top AWS Services by Check Count
| Service | Checks | Key Areas |
|---------|--------|-----------|
| ec2 | 70 | SG ports (17 specific), IMDSv2, EBS, Shodan, user data secrets |
| iam | 43 | Privesc detection, root MFA, password policy, key rotation, confused deputy |
| rds | 35 | Public access, encryption, multi-AZ, IAM auth, deprecated engines |
| cloudwatch | 22 | Log metric filters for 14 CIS alarm patterns |
| s3 | 21 | Public access, shadow resource, MFA delete, cross-account |
| cloudtrail | 14 | Threat detection (LLM jacking, privesc, enumeration) |
| bedrock | 7 | Guardrail prompt attacks, sensitive info filters |

---

## ScoutSuite (NCC Group)

- **Checks:** AWS ~150, Azure ~100, GCP ~80
- **Approach:** Pull all cloud config via API, generate interactive HTML report
- **Key Differences from Prowler:**
  - Better visualization (interactive HTML dashboard)
  - Fewer checks but more curated
  - Good for one-time assessments
  - No remediation automation
  - No threat detection / behavioral analysis

---

## CloudSploit (Aqua Security)

- **Checks:** AWS ~200, Azure ~100, GCP ~80
- **Approach:** Plugin-based, each check is a standalone module
- **Key Differences:**
  - Simpler architecture (easy to add checks)
  - Part of Aqua Security platform
  - Good AWS Lambda/API Gateway checks
  - Less compliance mapping than Prowler

---

## Trivy (Aqua Security)

- **Focus:** Container + IaC + Cloud misconfiguration scanner
- **Cloud Checks:** ~300 (AWS, Azure, GCP via Rego policies)
- **Key Differences:**
  - Best for container image vulnerability scanning
  - IaC scanning (Terraform, CloudFormation, ARM templates)
  - Kubernetes manifest security
  - Unified scanner (containers + IaC + cloud + SBOM)
  - Rego-based custom policies

---

## Steampipe (Turbot)

- **Approach:** SQL-based cloud querying + benchmark mods
- **Benchmarks:** CIS, NIST, PCI-DSS, HIPAA, FedRAMP, SOC2
- **Key Differences:**
  - SQL interface to cloud APIs (query like a database)
  - 150+ plugins for different services
  - Real-time querying (not snapshot-based)
  - Custom dashboards
  - Best for ad-hoc investigation

---

## Pacu (Rhino Security Labs)

- **Focus:** AWS exploitation framework (offensive)
- **Modules:** 40+ attack modules
- **Key Categories:**
  - IAM privilege escalation (21+ methods)
  - Credential harvesting (IMDS, Lambda env, Secrets Manager)
  - Persistence (backdoor users, access keys)
  - Lateral movement (EC2, Lambda, S3)
  - Data exfiltration (S3, RDS snapshots)
  - Reconnaissance (IAM enum, service enum)
- **Key Difference:** Offensive tool — tests exploitability, not just misconfiguration

---

## cloud-audit-mcp Differentiation

### What Makes MCP Different

| Feature | Prowler/ScoutSuite | cloud-audit-mcp |
|---------|-------------------|-----------------|
| **Interface** | CLI → static report | MCP → AI agent interactive |
| **Query Model** | Scan everything → filter | Agent asks targeted questions |
| **Context** | Each check independent | Agent correlates findings |
| **Remediation** | Provide fix command | Agent can explain WHY and chain impact |
| **Prioritization** | Severity label | Agent considers attack chains |
| **Interaction** | Run → wait → read 200 pages | "Find my top 5 risks and fix them" |
| **Scope** | Fixed check list | Agent can do custom investigation |

### Unique Value Propositions

1. **Interactive Investigation:** Agent can follow up on findings (e.g., "This S3 bucket is public — let me check what's in it")
2. **Attack Chain Analysis:** Agent connects findings (e.g., "Public S3 has SSH key → which EC2 instances does it grant access to?")
3. **Contextual Remediation:** Agent explains business impact + provides step-by-step fix
4. **Custom Checks:** Agent can create ad-hoc checks based on user's specific concerns
5. **Cross-Cloud Correlation:** Agent can check AWS + Azure + GCP in one conversation
6. **Natural Language:** User says "Am I safe?" instead of running 200 CLI commands

### Checks to Implement (Priority)

**From Prowler (not in HTB knowledge):**
- CloudTrail multi-region + log validation + encryption
- 14 CloudWatch log metric filter alarms (CIS Section 4)
- GuardDuty enabled all regions
- AWS Config enabled
- Root account MFA + no access keys
- RDS public access + encryption
- VPC flow logs
- Default SG restricts all
- KMS CMK rotation
- Bedrock guardrails (gen-ai)
- Shadow resource detection
- Dangling IP subdomain takeover

**From CIS/NIST (not in HTB knowledge):**
- Password policy enforcement
- Access key rotation ≤90 days
- Unused credentials cleanup
- IAM Access Analyzer
- Encryption at rest for all storage services
- TLS 1.2+ enforcement
- Audit log retention policies
- Network segmentation validation

**From MITRE ATT&CK (not in HTB knowledge):**
- Unused region resource detection (T1535)
- Logging tampering detection (T1562.008)
- Cryptomining detection (T1496)
- Cross-account snapshot sharing detection
- Golden SAML detection
