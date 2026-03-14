<p align="center">
  <br>
  <pre align="center">
     ██████╗██╗      ██████╗ ██╗   ██╗██████╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
    ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
    ██║     ██║     ██║   ██║██║   ██║██║  ██║    ███████║██║   ██║██║  ██║██║   ██║
    ██║     ██║     ██║   ██║██║   ██║██║  ██║    ██╔══██║██║   ██║██║  ██║██║   ██║
    ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝    ██║  ██║╚██████╔╝██████╔╝██║   ██║
     ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
  </pre>
</p>

<h3 align="center">Cloud security audit tools for AI agents.</h3>

<p align="center">
  Prowler gives you a 200-page PDF.<br>
  This gives your AI agent <b>direct access to cloud APIs</b> — it reads, correlates, and fixes.
</p>

<br>

<p align="center">
  <a href="#the-problem">The Problem</a> &bull;
  <a href="#how-its-different">How It's Different</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#what-the-ai-can-do">What The AI Can Do</a> &bull;
  <a href="#tools-reference-38-tools">Tools</a> &bull;
  <a href="#check-registry-60-checks">Checks</a> &bull;
  <a href="#architecture">Architecture</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/runtime-Bun-f472b6" alt="Bun">
  <img src="https://img.shields.io/badge/protocol-MCP-8b5cf6" alt="MCP">
  <img src="https://img.shields.io/badge/tools-38-22c55e" alt="38 Tools">
  <img src="https://img.shields.io/badge/checks-60+-ef4444" alt="60+ Checks">
  <img src="https://img.shields.io/badge/providers-AWS%20%7C%20Azure%20%7C%20GCP-f59e0b" alt="AWS | Azure | GCP">
</p>

---

## The Problem

Cloud security tools haven't changed in a decade. You run Prowler, wait 30 minutes, get a 200-page report, and then **you** have to read it, understand it, prioritize it, and fix it. Every. Single. Time.

```
Traditional workflow:
  prowler aws --compliance cis_3.0       →  200 findings, 40 pages
  you read the report                    →  2 hours
  you figure out what matters            →  30 minutes
  you write the fix commands             →  1 hour
  you run them                           →  30 minutes
  ─────────────────────────────────────
  Total: 4+ hours of your time
```

**cloud-audit-mcp** eliminates the human bottleneck. Your AI agent calls the cloud APIs directly, understands what it finds, chains checks together, and tells you exactly what to fix — in seconds.

```
With cloud-audit-mcp:
  You: "Check my AWS account for critical misconfigurations and fix them"

  Agent: → calls aws_check_s3_public, aws_check_iam_policies, aws_check_ec2_imds...
         → correlates: "This Lambda has admin role AND secrets in env vars"
         → prioritizes: "3 critical, 5 high — here's the impact of each"
         → "Run these 3 commands to fix the critical ones"
```

---

## How It's Different

Every existing tool is designed for **humans to read reports**. cloud-audit-mcp is designed for **AI agents to take action**.

<table>
<thead>
<tr>
<th></th>
<th>Prowler / ScoutSuite / CloudSploit</th>
<th>cloud-audit-mcp</th>
</tr>
</thead>
<tbody>
<tr>
<td><b>Interface</b></td>
<td>CLI → static report (PDF/HTML/JSON)</td>
<td>MCP → AI agent calls tools in real-time</td>
</tr>
<tr>
<td><b>Intelligence</b></td>
<td>Run all checks, dump results</td>
<td>Agent picks which checks to run based on context</td>
</tr>
<tr>
<td><b>Correlation</b></td>
<td>None — each finding is isolated</td>
<td>Agent chains findings: "This public S3 + this Lambda role = data exfil path"</td>
</tr>
<tr>
<td><b>Remediation</b></td>
<td>Generic advice</td>
<td>Agent generates exact CLI commands for your resources</td>
</tr>
<tr>
<td><b>Follow-up</b></td>
<td>Re-run the entire scan</td>
<td>Agent re-checks the specific resource after fix</td>
</tr>
<tr>
<td><b>Multi-cloud</b></td>
<td>Separate tools per cloud</td>
<td>Unified interface — AWS + Azure + GCP in one conversation</td>
</tr>
<tr>
<td><b>Scope</b></td>
<td>Compliance-focused (CIS benchmarks)</td>
<td>Offensive-focused — privilege escalation paths, credential exposure, attack chains</td>
</tr>
</tbody>
</table>

<br>

<details>
<summary>Specific comparisons with popular tools</summary>

<br>

| Tool | Stars | What it does | What it can't do |
|---|---|---|---|
| [Prowler](https://github.com/prowler-cloud/prowler) | 11k | 500+ CIS/compliance checks for AWS/Azure/GCP/K8s | Static report, no AI integration, no finding correlation |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | 6k | Multi-cloud audit with HTML dashboard | Offline report, no real-time interaction, ~100 checks |
| [CloudSploit](https://github.com/aquasecurity/cloudsploit) | 3k | 150+ checks across 6 clouds | Plugin-per-check, no cross-check intelligence |
| [Steampipe](https://github.com/turbot/steampipe) | 7k | SQL queries against cloud APIs, 1500+ controls | Requires SQL knowledge, no autonomous analysis |
| [Cartography](https://github.com/cartography-cncf/cartography) | 3k | Neo4j graph of cloud resources + relationships | Requires Neo4j/Cypher, no predefined security checks |
| [Trivy](https://github.com/aquasecurity/trivy) | 24k | Container/IaC/cloud vulnerability scanner | Primarily CVE scanning, limited misconfig checks |

All of these are excellent tools. cloud-audit-mcp doesn't replace them — it fills a gap none of them address: **giving an AI agent direct, interactive access to cloud security checks**.

</details>

---

## Quick Start

### Install

```bash
git clone https://github.com/badchars/cloud-audit-mcp.git
cd cloud-audit-mcp
bun install
```

### Connect to your AI agent

<details open>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add cloud-audit bun run /path/to/cloud-audit-mcp/src/index.ts
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cloud-audit": {
      "command": "bun",
      "args": ["run", "/path/to/cloud-audit-mcp/src/index.ts"],
      "env": {
        "AWS_PROFILE": "your-profile"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Cursor / Windsurf / other MCP clients</b></summary>

Same JSON config format. Point the command to your installation path.

</details>

### Set up cloud credentials

The MCP server uses your existing cloud credentials. No extra API keys needed.

```bash
# AWS — any of these:
aws configure                              # interactive setup
export AWS_PROFILE=my-profile              # named profile
export AWS_ACCESS_KEY_ID=...               # explicit keys

# Azure
export AZURE_SUBSCRIPTION_ID=...           # required
az login                                   # interactive login (recommended)
# or: AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET

# GCP
export GCP_PROJECT_ID=my-project           # required
gcloud auth application-default login      # interactive login (recommended)
# or: GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
```

### Start auditing

```
You: "Check my AWS account for critical security issues"
```

That's it. The agent handles the rest.

---

## What The AI Can Do

### Targeted Security Audit

```
You: "I'm worried about data exposure in our S3 buckets and Lambda functions"

Agent: → aws_check_s3_public
         Found 2 public buckets: "staging-assets" and "client-uploads"
       → aws_check_s3_objects
         "client-uploads" contains 847 .sql files and 12 .pem files
       → aws_check_lambda_env
         Lambda "process-uploads" has DATABASE_URL with plaintext credentials
       → "Critical: Your upload pipeline has public S3 + Lambda with DB creds.
          An attacker could download SQL dumps AND get your database password.
          Fix: 1) Block public access  2) Move creds to Secrets Manager"
```

### Multi-Cloud Posture Review

```
You: "Audit all three cloud accounts and give me the top 10 issues"

Agent: → cloud_run_all {provider: "aws"}     (13 checks)
       → cloud_run_all {provider: "azure"}   (13 checks)
       → cloud_run_all {provider: "gcp"}     (8 checks)
       → cloud_audit_summary
       → cloud_audit_report
       → "34 total findings across 3 clouds.
          Top 3 critical:
          1. AWS: IAM policy allows privilege escalation via CreatePolicyVersion
          2. Azure: SQL Server firewall allows 0.0.0.0/0
          3. GCP: 4 instances have cloud-platform scope (full API access)"
```

### Privilege Escalation Detection

```
You: "Can anyone escalate privileges in our AWS account?"

Agent: → aws_check_iam_policies
         Found PassRole + CreateFunction combo on role "dev-deploy-role"
         Found CreatePolicyVersion on user "ci-bot"
       → aws_check_lambda_permissions
         "ci-bot" has UpdateFunctionCode on all Lambda functions
       → "Two escalation paths:
          1. dev-deploy-role can create a Lambda with any role → admin
          2. ci-bot can inject code into any Lambda AND create policy versions
          Both should be restricted immediately."
```

### Pre-Pentest Cloud Recon

```
You: "We have a pentest next week. What would an attacker find?"

Agent: → aws_check_ec2_imds        → 12 instances with IMDSv1 (SSRF → creds)
       → aws_check_ec2_snapshots   → 3 unencrypted public snapshots
       → aws_check_api_gateway     → 7 endpoints with no auth
       → aws_check_secrets_manager → 1 secret with Principal: "*"
       → "Attacker's likely path: public API Gateway → SSRF on EC2 →
          IMDSv1 credential theft → access SecretsManager secret →
          pivot to production database. Priority fixes: IMDSv2 + API auth"
```

### Azure Container Security

```
You: "Check our Azure container infrastructure"

Agent: → azure_check_acr       → Admin user enabled on 2 registries
       → azure_check_functions → 3 Function Apps with anonymous auth
       → azure_check_keyvault  → Key Vault allows all networks
       → azure_check_webapp    → SCM basic auth enabled, 5 connection strings with passwords
       → "Your container supply chain is exposed:
          ACR admin creds can push malicious images,
          Functions run without auth, and Key Vault is network-open."
```

### GCP Kubernetes Audit

```
You: "How secure are our GKE clusters?"

Agent: → gcp_check_kubernetes   → Legacy ABAC enabled, no Workload Identity
       → gcp_check_metadata     → 8 nodes with cloud-platform scope
       → gcp_check_iam_keys     → 3 SA keys older than 365 days
       → gcp_check_iam_delegation → Token Creator role on 2 SAs
       → "Your GKE setup has multiple escalation paths:
          Pods use node SA with full cloud-platform scope → can access all GCP APIs.
          Workload Identity not configured → any pod can steal node credentials.
          Recommendation: Enable Workload Identity + restrict scopes."
```

---

## Tools Reference (38 tools)

### AWS (13 tools)

| Tool | Service | Checks | Severity |
|------|---------|--------|----------|
| `aws_check_s3_public` | S3 | Block Public Access, bucket policy, ACL | CRITICAL |
| `aws_check_s3_objects` | S3 | Sensitive files (.pem, .sql, .env, backups) | CRITICAL |
| `aws_check_iam_policies` | IAM | Privilege escalation paths, dangerous combos | CRITICAL |
| `aws_check_ec2_imds` | EC2 | IMDSv1 enabled (credential theft via SSRF) | CRITICAL |
| `aws_check_ec2_snapshots` | EC2 | Unencrypted / publicly shared EBS snapshots | CRITICAL |
| `aws_check_ec2_security_groups` | EC2 | 0.0.0.0/0 ingress on dangerous ports | HIGH |
| `aws_check_lambda_env` | Lambda | Secrets in environment variables | CRITICAL |
| `aws_check_lambda_permissions` | Lambda | UpdateFunctionCode, event source risks | HIGH |
| `aws_check_ecr_images` | ECR | Image scan findings, scan configuration | HIGH |
| `aws_check_secrets_manager` | Secrets Manager | Over-permissive resource policies | HIGH |
| `aws_check_dynamodb` | DynamoDB | Encryption settings, stream exposure | HIGH |
| `aws_check_api_gateway` | API Gateway | Endpoints without authentication | HIGH |
| `aws_check_sagemaker` | SageMaker | Internet access, root access, encryption | HIGH |

### Azure (13 tools)

| Tool | Service | Checks | Severity |
|------|---------|--------|----------|
| `azure_check_storage_public` | Storage | Public blob access, container access level | CRITICAL |
| `azure_check_storage_sas` | Storage | Long-lived SAS tokens, shared key access | HIGH |
| `azure_check_automation` | Automation | Hardcoded creds in runbooks, DSC plaintext, unencrypted vars | CRITICAL |
| `azure_check_vm_network` | VM / NSG | Management ports (SSH/RDP/WinRM) exposed to internet | CRITICAL |
| `azure_check_vm_encryption` | VM | Unencrypted OS and data disks | HIGH |
| `azure_check_vm_identity` | VM | Over-privileged managed identities, IMDS exposure | CRITICAL |
| `azure_check_ad_consent` | Entra ID | OAuth consent settings, secrets in descriptions | HIGH |
| `azure_check_logic_apps` | Logic Apps | SSRF via managed identity + HTTP triggers | CRITICAL |
| `azure_check_functions` | Functions | Anonymous auth, Key Vault reference injection | CRITICAL |
| `azure_check_keyvault` | Key Vault | Permissive access policies, network exposure | MEDIUM |
| `azure_check_acr` | Container Registry | Admin user enabled, image secrets | HIGH |
| `azure_check_sql` | SQL Database | SQL auth mode, firewall 0.0.0.0 rules | CRITICAL |
| `azure_check_webapp` | App Service | SCM basic auth, connection string creds, deployment packages | HIGH |

### GCP (8 tools)

| Tool | Service | Checks | Severity |
|------|---------|--------|----------|
| `gcp_check_gcs_public` | Cloud Storage | allUsers / allAuthenticatedUsers IAM bindings | CRITICAL |
| `gcp_check_gcs_objects` | Cloud Storage | SA key files, sensitive data in buckets | CRITICAL |
| `gcp_check_metadata` | Compute Engine | Startup script secrets, cloud-platform scope, legacy metadata | CRITICAL |
| `gcp_check_iam_keys` | IAM | SA key age, user-managed key audit | HIGH |
| `gcp_check_iam_delegation` | IAM | SA impersonation chains, Token Creator abuse | CRITICAL |
| `gcp_check_iam_compute` | IAM | setMetadata permission (SSH key injection) | HIGH |
| `gcp_check_kubernetes` | GKE | Legacy ABAC, Workload Identity, privileged pods, network policy | CRITICAL |
| `gcp_check_gcr` | Container Registry | Public access, suspicious images | HIGH |

### Meta (4 tools)

| Tool | Description |
|------|-------------|
| `cloud_list_checks` | List all available checks, filterable by provider / severity / priority |
| `cloud_run_all` | Run all checks for a provider in one call |
| `cloud_audit_summary` | Aggregate findings by status, provider, severity |
| `cloud_audit_report` | Generate markdown or JSON report from session findings |

---

## Check Registry (60+ checks)

Every check maps to industry standards where applicable.

<details>
<summary><b>AWS — 19 checks</b></summary>

| ID | Check | Severity | Priority | References |
|----|-------|----------|----------|------------|
| S3-001 | Public bucket access (ACL + policy + Block Public Access) | CRITICAL | P0 | CIS 2.1.4, NIST AC-3 |
| S3-002 | Sensitive objects in S3 (SSH keys, SQL dumps) | CRITICAL | P0 | OWASP Cloud-2 |
| S3-003 | Bucket name leaks account ID | LOW | P2 | |
| IAM-001 | Policy version privilege escalation | CRITICAL | P0 | MITRE T1098 |
| IAM-002 | Dangerous permission combos (PassRole+CreateFunction) | CRITICAL | P0 | Rhino Security |
| IAM-003 | Lambda execution roles with admin access | HIGH | P1 | CIS 1.16 |
| EC2-001 | IMDSv1 enabled (SSRF → credential theft) | CRITICAL | P0 | CIS 5.6, MITRE T1552.005 |
| EC2-002 | Unencrypted / publicly shared EBS snapshots | CRITICAL | P0 | CIS 2.2.1 |
| EC2-003 | Security groups with 0.0.0.0/0 ingress | HIGH | P1 | CIS 5.1-5.3 |
| LAMBDA-001 | Secrets in Lambda environment variables | CRITICAL | P0 | MITRE T1552.001 |
| LAMBDA-002 | UpdateFunctionCode permission | CRITICAL | P0 | Rhino Security |
| LAMBDA-003 | Event source mapping as invocation bypass | HIGH | P1 | Rhino Security |
| ECR-001 | Image scan findings | CRITICAL | P0 | OWASP Cloud-3 |
| ECR-002 | Image scanning configuration | MEDIUM | P2 | OWASP Cloud-3 |
| SM-001 | Over-permissive secret access policies | HIGH | P1 | CIS 2.4 |
| DYNAMO-001 | DynamoDB encryption settings | HIGH | P1 | NIST SC-28 |
| DYNAMO-002 | DynamoDB streams data flow | HIGH | P1 | |
| APIGW-001 | API endpoints without authentication | HIGH | P1 | OWASP Cloud-8 |
| SAGE-001 | SageMaker notebook access + root | HIGH | P1 | |

</details>

<details>
<summary><b>Azure — 24 checks</b></summary>

| ID | Check | Severity | Priority | References |
|----|-------|----------|----------|------------|
| STOR-001 | Public blob access enabled | CRITICAL | P0 | CIS 3.2, ASB NS-2 |
| STOR-002 | Container public access level | CRITICAL | P0 | CIS 3.2 |
| STOR-003 | Long-lived SAS tokens | HIGH | P1 | CIS 3.7 |
| AUTO-001 | Hardcoded credentials in runbooks | HIGH | P1 | |
| AUTO-002 | DSC configuration plaintext passwords | CRITICAL | P0 | |
| AUTO-003 | Unencrypted automation variables | HIGH | P1 | |
| VM-001 | Management ports exposed (SSH/RDP/WinRM) | CRITICAL | P0 | CIS 6.1-6.2 |
| VM-002 | Unencrypted VM disks | HIGH | P1 | CIS 7.2 |
| VM-004 | Over-privileged managed identities | CRITICAL | P0 | ASB PA-1 |
| VM-005 | IMDS token theft exposure | HIGH | P1 | MITRE T1552.005 |
| AAD-001 | Secrets in AD object descriptions | HIGH | P1 | |
| AAD-002 | User consent settings (OAuth phishing) | HIGH | P1 | ASB IM-1 |
| LOGIC-001 | SSRF via managed identity | CRITICAL | P0 | |
| FUNC-001 | Anonymous auth on Functions | CRITICAL | P0 | CIS 9.1 |
| FUNC-002 | Key Vault reference injection | MEDIUM | P2 | |
| KV-001 | Overly permissive Key Vault access | MEDIUM | P2 | CIS 8.3 |
| KV-002 | Key Vault network unrestricted | MEDIUM | P2 | CIS 8.4 |
| ACR-001 | Admin user enabled | HIGH | P1 | CIS |
| ACR-002 | Secrets in container images | HIGH | P1 | |
| SQL-001 | SQL authentication enabled | HIGH | P1 | CIS 4.4 |
| SQL-002 | Overly permissive firewall rules | CRITICAL | P1 | CIS 6.3 |
| WEBAPP-001 | SCM basic auth enabled | MEDIUM | P2 | CIS 9.1 |
| WEBAPP-002 | Connection strings with credentials | HIGH | P1 | |
| WEBAPP-003 | Deployment packages in accessible storage | MEDIUM | P2 | |

</details>

<details>
<summary><b>GCP — 17 checks</b></summary>

| ID | Check | Severity | Priority | References |
|----|-------|----------|----------|------------|
| GCS-001 | Public bucket access (allUsers/allAuthenticatedUsers) | CRITICAL | P0 | CIS 5.1 |
| GCS-002 | SA keys in storage buckets | CRITICAL | P0 | OWASP Cloud-2 |
| GCS-003 | Sensitive files in buckets | HIGH | P1 | |
| META-001 | Startup script secrets | CRITICAL | P0 | MITRE T1552.001 |
| META-002 | Instance with cloud-platform scope | CRITICAL | P0 | CIS 4.2 |
| META-003 | Metadata concealment not enabled | HIGH | P1 | CIS 4.9 |
| IAM-001g | Service account key audit | HIGH | P1 | CIS 1.3-1.4 |
| IAM-002g | Delegation chain detection | CRITICAL | P0 | Rhino Security |
| IAM-003g | Token Creator role abuse | HIGH | P1 | Rhino Security |
| IAM-004g | setMetadata permission (SSH key injection) | CRITICAL | P0 | Rhino Security |
| K8S-001 | Default SA with cluster-admin | CRITICAL | P0 | CIS K8s 5.1 |
| K8S-002 | Privileged containers allowed | CRITICAL | P0 | CIS K8s 5.2 |
| K8S-003 | Secure Boot on node pools | HIGH | P1 | CIS K8s 4.2 |
| K8S-004 | SA token automount | MEDIUM | P2 | CIS K8s 5.1.6 |
| GCR-001 | Unexpected/hidden images in GCR | HIGH | P1 | |

</details>

---

## Architecture

```
cloud-audit-mcp/
├── src/
│   ├── index.ts                 Entry point + ToolContext builder
│   ├── types/
│   │   └── index.ts             CheckResult, Severity, ToolDef, ToolContext
│   ├── protocol/
│   │   ├── mcp-server.ts        MCP server (stdio transport)
│   │   └── tools.ts             38 tool definitions (Zod schemas)
│   ├── aws/                     13 tools, 10 files
│   │   ├── client.ts            Lazy SDK factory (cached per region)
│   │   ├── s3.ts                S3-001, S3-002, S3-003
│   │   ├── iam.ts               IAM-001, IAM-002, IAM-003
│   │   ├── ec2.ts               EC2-001, EC2-002, EC2-003
│   │   ├── lambda.ts            LAMBDA-001, LAMBDA-002, LAMBDA-003
│   │   ├── ecr.ts               ECR-001, ECR-002
│   │   ├── secrets.ts           SM-001
│   │   ├── dynamodb.ts          DYNAMO-001, DYNAMO-002
│   │   ├── apigw.ts             APIGW-001
│   │   └── sagemaker.ts         SAGE-001
│   ├── azure/                   13 tools, 11 files
│   │   ├── client.ts            DefaultAzureCredential factory
│   │   ├── storage.ts           STOR-001, STOR-002, STOR-003
│   │   ├── automation.ts        AUTO-001, AUTO-002, AUTO-003
│   │   ├── vm.ts                VM-001, VM-002, VM-004, VM-005
│   │   ├── ad.ts                AAD-001, AAD-002
│   │   ├── logic.ts             LOGIC-001
│   │   ├── functions.ts         FUNC-001, FUNC-002
│   │   ├── keyvault.ts          KV-001, KV-002
│   │   ├── acr.ts               ACR-001, ACR-002
│   │   ├── sql.ts               SQL-001, SQL-002
│   │   └── webapp.ts            WEBAPP-001, WEBAPP-002, WEBAPP-003
│   ├── gcp/                     8 tools, 6 files
│   │   ├── client.ts            ADC factory
│   │   ├── storage.ts           GCS-001, GCS-002, GCS-003
│   │   ├── metadata.ts          META-001, META-002, META-003
│   │   ├── iam.ts               IAM-001g, IAM-002g, IAM-003g, IAM-004g
│   │   ├── kubernetes.ts        K8S-001, K8S-002, K8S-003, K8S-004
│   │   └── gcr.ts               GCR-001
│   └── meta/                    4 tools
│       ├── list-checks.ts       Check registry (60+ entries)
│       ├── summary.ts           Finding aggregation
│       ├── report.ts            Markdown/JSON report generation
│       └── run-all.ts           Run all provider checks
└── knowledge/                   Security check knowledge base (8 files)
```

### Design Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| **1 tool per service** | 38 tools, not 60+ | LLM can pick the right tool without overwhelm |
| **Uniform CheckResult** | Same format across all clouds | Agent can compare and correlate across providers |
| **Session findings store** | In-memory array on ToolContext | Accumulate findings → summarize → report in one conversation |
| **Lazy client init** | SDK clients created on first use | No cold start penalty for unused providers |
| **Offensive focus** | Privilege escalation, credential exposure, attack chains | CIS compliance tools already exist — this finds what attackers find |
| **Default credentials** | AWS profiles, Azure CLI, gcloud ADC | Zero extra configuration — use what's already set up |
| **Error → CheckResult** | SDK errors become ERROR status, never crash | Agent sees all results, decides what matters |

### How It Works

```
┌──────────────────────────────────────────────────────────────┐
│                        AI Agent                               │
│                                                               │
│  "Check S3 for public access"                                │
│         │                                                     │
│         ▼                                                     │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐     │
│  │  MCP Client  │───▶│  MCP Server  │───▶│  Tool Router │     │
│  │  (stdio)     │    │  (38 tools)  │    │  (Zod valid) │     │
│  └─────────────┘    └──────────────┘    └──────┬───────┘     │
│                                                 │             │
│         ┌───────────────────┬───────────────────┤             │
│         ▼                   ▼                   ▼             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │  AWS Module  │    │ Azure Module│    │  GCP Module  │      │
│  │  (SDK v3)    │    │  (ARM SDK)  │    │  (Cloud SDK) │      │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘      │
│         │                   │                   │             │
│         ▼                   ▼                   ▼             │
│  ┌─────────────────────────────────────────────────────┐     │
│  │              CheckResult[] (uniform format)          │     │
│  │  { checkId, severity, status, resource, remediation }│     │
│  └──────────────────────┬──────────────────────────────┘     │
│                         │                                     │
│                         ▼                                     │
│  ┌─────────────────────────────────────────────────────┐     │
│  │           Findings Store (session-scoped)            │     │
│  │  → cloud_audit_summary → cloud_audit_report          │     │
│  └─────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

---

## Related Projects

| Project | Description |
|---------|-------------|
| [hackbrowser-mcp](https://github.com/badchars/hackbrowser-mcp) | Browser-based security testing MCP (39 tools, Firefox, injection testing) |
| [recon0](https://github.com/badchars/recon0) | Bug bounty recon pipeline |

---

## Limitations

- Read-only — does not modify cloud resources (by design)
- Requires existing cloud credentials (AWS profiles, Azure CLI, gcloud ADC)
- Azure AD checks (AAD-001, AAD-002) require Microsoft Graph API (stubbed)
- GCP IAM checks use REST API calls (not all exposed via SDK)
- Session findings are in-memory only (lost on restart)

---

<p align="center">
<b>For authorized security testing and cloud posture assessment only.</b><br>
Always ensure you have proper authorization before auditing cloud accounts.
</p>

<p align="center">
  <a href="LICENSE">MIT License</a> &bull;
  Built with Bun + TypeScript &bull;
  Part of <a href="https://www.amazon.com/dp/B0GFD44D84">Agentic AI for Offensive Cybersecurity</a>
</p>
