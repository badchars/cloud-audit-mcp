import type { CheckMeta, CloudProvider, Severity, Priority } from "../types/index.js";

const CHECK_REGISTRY: CheckMeta[] = [
  // ═══ AWS P0 ═══
  { id: "S3-001", provider: "aws", title: "Public bucket access (ACL + policy + Block Public Access)", severity: "CRITICAL", priority: "P0", description: "Check S3 buckets for public access via ACL, bucket policy, or missing Block Public Access settings", references: ["CIS 2.1.4", "NIST AC-3"] },
  { id: "S3-002", provider: "aws", title: "Sensitive objects in S3 (SSH keys, SQL dumps, source code)", severity: "CRITICAL", priority: "P0", description: "Scan S3 bucket objects for sensitive file patterns", references: ["OWASP Cloud-2"] },
  { id: "IAM-001", provider: "aws", title: "Policy version privilege escalation", severity: "CRITICAL", priority: "P0", description: "Check for IAM policies with CreatePolicyVersion/SetDefaultPolicyVersion permissions", references: ["MITRE T1098", "Rhino Security"] },
  { id: "IAM-002", provider: "aws", title: "Dangerous permission combos (PassRole+CreateFunction)", severity: "CRITICAL", priority: "P0", description: "Detect dangerous IAM permission combinations that enable privilege escalation", references: ["Rhino Security", "MITRE T1078"] },
  { id: "EC2-001", provider: "aws", title: "IMDSv1 enabled", severity: "CRITICAL", priority: "P0", description: "Check EC2 instances for IMDSv1 (credential theft via SSRF)", references: ["CIS 5.6", "MITRE T1552.005"] },
  { id: "EC2-002", provider: "aws", title: "Unencrypted/accessible EBS snapshots", severity: "CRITICAL", priority: "P0", description: "Check for unencrypted or publicly shared EBS snapshots", references: ["CIS 2.2.1"] },
  { id: "LAMBDA-001", provider: "aws", title: "Secrets in Lambda environment variables", severity: "CRITICAL", priority: "P0", description: "Scan Lambda function environment variables for hardcoded secrets", references: ["OWASP Cloud-2", "MITRE T1552.001"] },
  { id: "LAMBDA-002", provider: "aws", title: "UpdateFunctionCode permission", severity: "CRITICAL", priority: "P0", description: "Detect IAM entities with Lambda UpdateFunctionCode permission (code injection)", references: ["Rhino Security"] },
  { id: "ECR-001", provider: "aws", title: "Hardcoded credentials in Docker images", severity: "CRITICAL", priority: "P0", description: "Check ECR repositories for image scan findings", references: ["OWASP Cloud-3"] },

  // ═══ AWS P1 ═══
  { id: "IAM-003", provider: "aws", title: "Lambda execution roles with admin access", severity: "HIGH", priority: "P1", description: "Check for Lambda execution roles with AdministratorAccess policy", references: ["CIS 1.16"] },
  { id: "EC2-003", provider: "aws", title: "Security groups with 0.0.0.0/0", severity: "HIGH", priority: "P1", description: "Detect security groups allowing unrestricted inbound access", references: ["CIS 5.1-5.3"] },
  { id: "LAMBDA-003", provider: "aws", title: "Event source mapping as invocation bypass", severity: "HIGH", priority: "P1", description: "Check for Lambda event source mappings that could be used for indirect invocation", references: ["Rhino Security"] },
  { id: "SM-001", provider: "aws", title: "Over-permissive secret access", severity: "HIGH", priority: "P1", description: "Check Secrets Manager resource policies for overly broad access", references: ["CIS 2.4"] },
  { id: "DYNAMO-001", provider: "aws", title: "Cleartext credentials in DynamoDB tables", severity: "HIGH", priority: "P1", description: "Check DynamoDB table encryption settings", references: ["NIST SC-28"] },
  { id: "DYNAMO-002", provider: "aws", title: "DynamoDB streams to Lambda chains", severity: "HIGH", priority: "P1", description: "Detect DynamoDB streams that trigger Lambda functions (data flow risk)", references: [] },
  { id: "APIGW-001", provider: "aws", title: "API without authentication", severity: "HIGH", priority: "P1", description: "Check API Gateway methods for missing authentication", references: ["CIS", "OWASP Cloud-8"] },
  { id: "SAGE-001", provider: "aws", title: "SageMaker notebook instance access", severity: "HIGH", priority: "P1", description: "Check SageMaker notebook instances for direct internet access and root access", references: [] },

  // ═══ AWS P2 ═══
  { id: "S3-003", provider: "aws", title: "Bucket name leaks account ID", severity: "LOW", priority: "P2", description: "Check if S3 bucket names contain AWS account ID patterns", references: [] },
  { id: "ECR-002", provider: "aws", title: "Sensitive files in image layers", severity: "MEDIUM", priority: "P2", description: "Check ECR image scanning configuration", references: ["OWASP Cloud-3"] },

  // ═══ Azure P0 ═══
  { id: "STOR-001", provider: "azure", title: "Public blob access enabled", severity: "CRITICAL", priority: "P0", description: "Check storage accounts for allowBlobPublicAccess setting", references: ["CIS 3.2", "ASB NS-2"] },
  { id: "STOR-002", provider: "azure", title: "Container public access level", severity: "CRITICAL", priority: "P0", description: "Check blob containers for public access level (blob/container)", references: ["CIS 3.2"] },
  { id: "AUTO-002", provider: "azure", title: "DSC configuration plaintext passwords", severity: "CRITICAL", priority: "P0", description: "Check Automation DSC configurations for plaintext credentials", references: [] },
  { id: "VM-001", provider: "azure", title: "Management ports exposed (WinRM/RDP/SSH)", severity: "CRITICAL", priority: "P0", description: "Check NSGs for exposed management ports from internet", references: ["CIS 6.1-6.2", "ASB NS-1"] },
  { id: "VM-004", provider: "azure", title: "Over-privileged managed identities", severity: "CRITICAL", priority: "P0", description: "Check VMs with managed identities for overly broad role assignments", references: ["ASB PA-1"] },
  { id: "LOGIC-001", provider: "azure", title: "SSRF via managed identity", severity: "CRITICAL", priority: "P0", description: "Check Logic Apps with HTTP triggers and managed identity (SSRF risk)", references: [] },
  { id: "FUNC-001", provider: "azure", title: "Anonymous auth level on functions", severity: "CRITICAL", priority: "P0", description: "Check Azure Functions for anonymous authentication level", references: ["CIS 9.1"] },

  // ═══ Azure P1 ═══
  { id: "STOR-003", provider: "azure", title: "Long-lived SAS tokens", severity: "HIGH", priority: "P1", description: "Check for SAS tokens with excessive validity periods", references: ["CIS 3.7"] },
  { id: "AUTO-001", provider: "azure", title: "Hardcoded credentials in runbooks", severity: "HIGH", priority: "P1", description: "Check Automation runbooks for hardcoded credential patterns", references: [] },
  { id: "AUTO-003", provider: "azure", title: "Automation variables unencrypted", severity: "HIGH", priority: "P1", description: "Check Automation variables for unencrypted sensitive values", references: [] },
  { id: "VM-002", provider: "azure", title: "Unencrypted VM disks", severity: "HIGH", priority: "P1", description: "Check VM disks for encryption at rest", references: ["CIS 7.2"] },
  { id: "VM-005", provider: "azure", title: "IMDS token theft exposure", severity: "HIGH", priority: "P1", description: "Check VMs with managed identity for IMDS token theft risk", references: ["MITRE T1552.005"] },
  { id: "AAD-001", provider: "azure", title: "Secrets in AD object descriptions", severity: "HIGH", priority: "P1", description: "Check Azure AD object descriptions for credential patterns (requires Graph API)", references: [] },
  { id: "AAD-002", provider: "azure", title: "User consent settings (OAuth phishing)", severity: "HIGH", priority: "P1", description: "Check Azure AD user consent settings for OAuth phishing risk (requires Graph API)", references: ["ASB IM-1"] },
  { id: "ACR-001", provider: "azure", title: "Admin user enabled", severity: "HIGH", priority: "P1", description: "Check container registries for admin user enabled", references: ["CIS"] },
  { id: "ACR-002", provider: "azure", title: "Secrets in container images", severity: "HIGH", priority: "P1", description: "Check container registry images for secrets (requires docker pull)", references: [] },
  { id: "SQL-001", provider: "azure", title: "SQL authentication enabled", severity: "HIGH", priority: "P1", description: "Check SQL servers for SQL authentication (should use Azure AD only)", references: ["CIS 4.4"] },
  { id: "SQL-002", provider: "azure", title: "Overly permissive firewall rules", severity: "HIGH", priority: "P1", description: "Check SQL server firewall rules for 0.0.0.0 ranges", references: ["CIS 6.3"] },
  { id: "WEBAPP-002", provider: "azure", title: "Connection strings with credentials", severity: "HIGH", priority: "P1", description: "Check web app connection strings for embedded credentials", references: [] },

  // ═══ Azure P2 ═══
  { id: "FUNC-002", provider: "azure", title: "User input passed to Key Vault", severity: "MEDIUM", priority: "P2", description: "Check Function Apps for Key Vault references that may be injectable", references: [] },
  { id: "KV-001", provider: "azure", title: "Overly permissive Key Vault access", severity: "MEDIUM", priority: "P2", description: "Check Key Vault access policies for overly broad permissions", references: ["CIS 8.3"] },
  { id: "KV-002", provider: "azure", title: "Key Vault network access not restricted", severity: "MEDIUM", priority: "P2", description: "Check Key Vault network ACLs for unrestricted access", references: ["CIS 8.4"] },
  { id: "WEBAPP-001", provider: "azure", title: "SCM basic auth enabled", severity: "MEDIUM", priority: "P2", description: "Check web apps for SCM basic authentication enabled", references: ["CIS 9.1"] },
  { id: "WEBAPP-003", provider: "azure", title: "Deployment packages in accessible storage", severity: "MEDIUM", priority: "P2", description: "Check web app deployment configuration for accessible storage", references: [] },

  // ═══ GCP P0 ═══
  { id: "GCS-001", provider: "gcp", title: "Public bucket access (allUsers/allAuthenticatedUsers)", severity: "CRITICAL", priority: "P0", description: "Check GCS buckets for public IAM bindings", references: ["CIS 5.1"] },
  { id: "GCS-002", provider: "gcp", title: "SA keys in storage buckets", severity: "CRITICAL", priority: "P0", description: "Scan GCS buckets for service account key files", references: ["OWASP Cloud-2"] },
  { id: "META-001", provider: "gcp", title: "Startup script secrets", severity: "CRITICAL", priority: "P0", description: "Check GCE instance startup scripts for hardcoded secrets", references: ["MITRE T1552.001"] },
  { id: "META-002", provider: "gcp", title: "Instance with cloud-platform scope", severity: "CRITICAL", priority: "P0", description: "Check GCE instances for overly broad cloud-platform scope", references: ["CIS 4.2"] },
  { id: "IAM-002g", provider: "gcp", title: "Delegation chain detection", severity: "CRITICAL", priority: "P0", description: "Detect service account impersonation chains", references: ["Rhino Security"] },
  { id: "IAM-004g", provider: "gcp", title: "setMetadata permission (SSH key injection)", severity: "CRITICAL", priority: "P0", description: "Check for IAM bindings with compute.instances.setMetadata permission", references: ["Rhino Security"] },
  { id: "K8S-001", provider: "gcp", title: "Default SA with cluster-admin", severity: "CRITICAL", priority: "P0", description: "Check GKE clusters for default SA with cluster-admin binding", references: ["CIS K8s 5.1"] },
  { id: "K8S-002", provider: "gcp", title: "Privileged containers allowed", severity: "CRITICAL", priority: "P0", description: "Check GKE clusters for privileged container allowance", references: ["CIS K8s 5.2"] },

  // ═══ GCP P1 ═══
  { id: "GCS-003", provider: "gcp", title: "Sensitive files in buckets", severity: "HIGH", priority: "P1", description: "Scan GCS buckets for sensitive file patterns", references: [] },
  { id: "IAM-001g", provider: "gcp", title: "Service account key audit", severity: "HIGH", priority: "P1", description: "Audit service account keys for age and usage", references: ["CIS 1.3-1.4"] },
  { id: "IAM-003g", provider: "gcp", title: "Token Creator role abuse", severity: "HIGH", priority: "P1", description: "Check for serviceAccountTokenCreator role bindings", references: ["Rhino Security"] },
  { id: "META-003", provider: "gcp", title: "Metadata concealment not enabled", severity: "HIGH", priority: "P1", description: "Check if workload identity / metadata concealment is configured", references: ["CIS 4.9"] },
  { id: "K8S-003", provider: "gcp", title: "Kubelet API exposure", severity: "HIGH", priority: "P1", description: "Check GKE node configuration for secure boot", references: ["CIS K8s 4.2"] },
  { id: "GCR-001", provider: "gcp", title: "Unexpected/hidden images in GCR", severity: "HIGH", priority: "P1", description: "Check for unexpected images in Google Container Registry", references: [] },

  // ═══ GCP P2 ═══
  { id: "K8S-004", provider: "gcp", title: "SA token automount", severity: "MEDIUM", priority: "P2", description: "Check GKE default SA token automount settings", references: ["CIS K8s 5.1.6"] },
];

export function listChecks(args: {
  provider?: string;
  severity?: string;
  priority?: string;
}): CheckMeta[] {
  let checks = CHECK_REGISTRY;

  if (args.provider) {
    checks = checks.filter(c => c.provider === args.provider);
  }
  if (args.severity) {
    const sev = args.severity.toUpperCase();
    checks = checks.filter(c => c.severity === sev);
  }
  if (args.priority) {
    const pri = args.priority.toUpperCase();
    checks = checks.filter(c => c.priority === pri);
  }

  return checks;
}

export function getCheckMeta(checkId: string): CheckMeta | undefined {
  return CHECK_REGISTRY.find(c => c.id === checkId);
}

export { CHECK_REGISTRY };
