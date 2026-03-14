import type { CheckResult } from "../types/index.js";
import type { GcpClientFactory } from "./client.js";
import { GoogleAuth } from "google-auth-library";

const KEY_MAX_AGE_DAYS = 90;

interface ServiceAccount {
  name: string;
  email: string;
  uniqueId: string;
  disabled?: boolean;
}

interface ServiceAccountKey {
  name: string;
  keyAlgorithm: string;
  keyOrigin: string;
  keyType: string;
  validAfterTime: string;
  validBeforeTime: string;
}

interface IamBinding {
  role: string;
  members: string[];
  condition?: { title: string; expression: string };
}

interface IamPolicy {
  bindings: IamBinding[];
  version: number;
}

/**
 * Get an authenticated access token for GCP REST API calls.
 */
async function getAccessToken(): Promise<string> {
  const auth = new GoogleAuth({
    scopes: ["https://www.googleapis.com/auth/cloud-platform"],
  });
  const client = await auth.getClient();
  const token = await client.getAccessToken();
  return token.token ?? "";
}

/**
 * Helper: fetch JSON from a GCP REST API endpoint with auth.
 */
async function gcpFetch<T>(url: string, accessToken: string, method = "GET", body?: unknown): Promise<T> {
  const opts: RequestInit = {
    method,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  };
  if (body) {
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(url, opts);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`GCP API ${method} ${url} returned ${resp.status}: ${text}`);
  }
  return resp.json() as T;
}

/**
 * IAM-001g: Service account key audit
 * Lists all service accounts and their user-managed keys, flags keys older than 90 days.
 */
export async function checkIamKeys(
  gcp: GcpClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const project = gcp.getProjectId();

  let accessToken: string;
  try {
    accessToken = await getAccessToken();
  } catch (err) {
    results.push({
      checkId: "IAM-001g",
      title: "Service account key audit",
      severity: "HIGH",
      status: "ERROR",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: `Failed to obtain access token: ${(err as Error).message}`,
      remediation: "Ensure Application Default Credentials are configured: gcloud auth application-default login",
    });
    return results;
  }

  // List service accounts
  let serviceAccounts: ServiceAccount[] = [];
  try {
    const url = `https://iam.googleapis.com/v1/projects/${project}/serviceAccounts?pageSize=100`;
    const resp = await gcpFetch<{ accounts?: ServiceAccount[] }>(url, accessToken);
    serviceAccounts = resp.accounts ?? [];
  } catch (err) {
    results.push({
      checkId: "IAM-001g",
      title: "Service account key audit",
      severity: "HIGH",
      status: "ERROR",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: `Failed to list service accounts: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: iam.serviceAccounts.list",
    });
    return results;
  }

  if (serviceAccounts.length === 0) {
    results.push({
      checkId: "IAM-001g",
      title: "Service account key audit",
      severity: "HIGH",
      status: "NOT_APPLICABLE",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: "No service accounts found in the project.",
      remediation: "No action required.",
    });
    return results;
  }

  for (const sa of serviceAccounts) {
    const saEmail = sa.email;
    const saResource = `projects/${project}/serviceAccounts/${saEmail}`;

    try {
      const keysUrl = `https://iam.googleapis.com/v1/projects/${project}/serviceAccounts/${saEmail}/keys`;
      const keysResp = await gcpFetch<{ keys?: ServiceAccountKey[] }>(keysUrl, accessToken);
      const keys = keysResp.keys ?? [];

      // Filter to user-managed keys only (exclude GCP-managed SYSTEM_MANAGED keys)
      const userKeys = keys.filter((k) => k.keyType === "USER_MANAGED");

      if (userKeys.length === 0) {
        results.push({
          checkId: "IAM-001g",
          title: "Service account key audit",
          severity: "HIGH",
          status: "PASS",
          resource: saResource,
          region: "global",
          provider: "gcp",
          details: `Service account ${saEmail} has no user-managed keys.`,
          remediation: "No action required.",
        });
        continue;
      }

      // Check key age
      const now = Date.now();
      for (const key of userKeys) {
        const createdAt = new Date(key.validAfterTime).getTime();
        const ageDays = Math.floor((now - createdAt) / (1000 * 60 * 60 * 24));
        const keyId = key.name.split("/").pop() ?? key.name;

        if (ageDays > KEY_MAX_AGE_DAYS) {
          results.push({
            checkId: "IAM-001g",
            title: "Service account key audit",
            severity: "HIGH",
            status: "FAIL",
            resource: saResource,
            region: "global",
            provider: "gcp",
            details: `Service account ${saEmail} has user-managed key "${keyId}" that is ${ageDays} days old (threshold: ${KEY_MAX_AGE_DAYS} days).`,
            remediation: `Rotate or delete the old key:\ngcloud iam service-accounts keys delete ${keyId} --iam-account=${saEmail}\n\nConsider using Workload Identity Federation instead of exported keys.`,
            reference: "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",
          });
        } else {
          results.push({
            checkId: "IAM-001g",
            title: "Service account key audit",
            severity: "HIGH",
            status: "FAIL",
            resource: saResource,
            region: "global",
            provider: "gcp",
            details: `Service account ${saEmail} has user-managed key "${keyId}" (${ageDays} days old). User-managed keys are a security risk regardless of age.`,
            remediation: `Delete the key and use Workload Identity Federation:\ngcloud iam service-accounts keys delete ${keyId} --iam-account=${saEmail}`,
            reference: "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",
          });
        }
      }
    } catch (err) {
      results.push({
        checkId: "IAM-001g",
        title: "Service account key audit",
        severity: "HIGH",
        status: "ERROR",
        resource: saResource,
        region: "global",
        provider: "gcp",
        details: `Failed to list keys for ${saEmail}: ${(err as Error).message}`,
        remediation: "Verify IAM permissions: iam.serviceAccountKeys.list",
      });
    }
  }

  return results;
}

/**
 * IAM-002g: Delegation chain detection
 * IAM-003g: Token Creator role abuse
 * Checks project IAM policy for dangerous role bindings:
 * - roles/iam.serviceAccountTokenCreator (can impersonate any SA)
 * - iam.serviceAccounts.implicitDelegation / getAccessToken permissions
 */
export async function checkIamDelegation(
  gcp: GcpClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const project = gcp.getProjectId();

  let accessToken: string;
  try {
    accessToken = await getAccessToken();
  } catch (err) {
    results.push({
      checkId: "IAM-002g",
      title: "Delegation chain detection",
      severity: "CRITICAL",
      status: "ERROR",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: `Failed to obtain access token: ${(err as Error).message}`,
      remediation: "Ensure Application Default Credentials are configured.",
    });
    return results;
  }

  let policy: IamPolicy;
  try {
    const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${project}:getIamPolicy`;
    policy = await gcpFetch<IamPolicy>(url, accessToken, "POST", {
      options: { requestedPolicyVersion: 3 },
    });
  } catch (err) {
    results.push({
      checkId: "IAM-002g",
      title: "Delegation chain detection",
      severity: "CRITICAL",
      status: "ERROR",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: `Failed to get project IAM policy: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: resourcemanager.projects.getIamPolicy",
    });
    return results;
  }

  const bindings = policy.bindings ?? [];

  // Dangerous roles to flag
  const dangerousRoles: Record<string, { checkId: string; title: string; severity: "CRITICAL" | "HIGH"; detail: string }> = {
    "roles/iam.serviceAccountTokenCreator": {
      checkId: "IAM-003g",
      title: "Token Creator role abuse",
      severity: "CRITICAL",
      detail: "Can generate access tokens, ID tokens, and sign JWTs/blobs for any service account. Enables full impersonation.",
    },
    "roles/iam.serviceAccountUser": {
      checkId: "IAM-002g",
      title: "Delegation chain detection",
      severity: "HIGH",
      detail: "Can run operations as a service account (attach SA to resources). Can be chained for privilege escalation.",
    },
    "roles/iam.serviceAccountKeyAdmin": {
      checkId: "IAM-002g",
      title: "Delegation chain detection",
      severity: "CRITICAL",
      detail: "Can create and manage service account keys. Can export keys for any SA in the project.",
    },
    "roles/owner": {
      checkId: "IAM-002g",
      title: "Delegation chain detection",
      severity: "CRITICAL",
      detail: "Full owner access to all resources. Includes all IAM permissions including SA impersonation.",
    },
    "roles/editor": {
      checkId: "IAM-002g",
      title: "Delegation chain detection",
      severity: "HIGH",
      detail: "Broad editor access. While it doesn't include IAM admin, it can modify many resource configurations.",
    },
  };

  let foundDangerous = false;

  for (const binding of bindings) {
    const role = binding.role;
    const config = dangerousRoles[role];
    if (!config) continue;

    foundDangerous = true;
    const saMembers = binding.members.filter(
      (m) => m.startsWith("serviceAccount:") || m.startsWith("user:") || m.startsWith("group:"),
    );

    if (saMembers.length > 0) {
      results.push({
        checkId: config.checkId,
        title: config.title,
        severity: config.severity,
        status: "FAIL",
        resource: `projects/${project}`,
        region: "global",
        provider: "gcp",
        details: `${config.detail}\nMembers with this role: ${saMembers.join(", ")}`,
        remediation: `Review and restrict role binding:\ngcloud projects remove-iam-policy-binding ${project} --role="${role}" --member="<MEMBER>"\n\nUse least-privilege custom roles instead.`,
        reference: "https://cloud.google.com/iam/docs/understanding-roles#service-account-roles",
      });
    }
  }

  if (!foundDangerous) {
    results.push({
      checkId: "IAM-002g",
      title: "Delegation chain detection",
      severity: "CRITICAL",
      status: "PASS",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: "No dangerous service account delegation roles found in project IAM policy.",
      remediation: "No action required.",
    });
    results.push({
      checkId: "IAM-003g",
      title: "Token Creator role abuse",
      severity: "CRITICAL",
      status: "PASS",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: "No Token Creator role bindings found in project IAM policy.",
      remediation: "No action required.",
    });
  }

  return results;
}

/**
 * IAM-004g: setMetadata permission check
 * Checks if any SA or user has compute.instances.setMetadata, which can be used
 * to modify startup scripts and inject code on running instances.
 */
export async function checkIamCompute(
  gcp: GcpClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const project = gcp.getProjectId();

  let accessToken: string;
  try {
    accessToken = await getAccessToken();
  } catch (err) {
    results.push({
      checkId: "IAM-004g",
      title: "setMetadata permission check",
      severity: "HIGH",
      status: "ERROR",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: `Failed to obtain access token: ${(err as Error).message}`,
      remediation: "Ensure Application Default Credentials are configured.",
    });
    return results;
  }

  let policy: IamPolicy;
  try {
    const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${project}:getIamPolicy`;
    policy = await gcpFetch<IamPolicy>(url, accessToken, "POST", {
      options: { requestedPolicyVersion: 3 },
    });
  } catch (err) {
    results.push({
      checkId: "IAM-004g",
      title: "setMetadata permission check",
      severity: "HIGH",
      status: "ERROR",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: `Failed to get project IAM policy: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: resourcemanager.projects.getIamPolicy",
    });
    return results;
  }

  // Roles that include compute.instances.setMetadata
  const setMetadataRoles = [
    "roles/compute.admin",
    "roles/compute.instanceAdmin",
    "roles/compute.instanceAdmin.v1",
    "roles/owner",
    "roles/editor",
  ];

  const bindings = policy.bindings ?? [];
  const flaggedMembers: { role: string; members: string[] }[] = [];

  for (const binding of bindings) {
    if (setMetadataRoles.includes(binding.role)) {
      const relevantMembers = binding.members.filter(
        (m) => m.startsWith("serviceAccount:") || m.startsWith("user:") || m.startsWith("group:"),
      );
      if (relevantMembers.length > 0) {
        flaggedMembers.push({ role: binding.role, members: relevantMembers });
      }
    }
  }

  if (flaggedMembers.length > 0) {
    const details = flaggedMembers
      .map((f) => `${f.role}: ${f.members.join(", ")}`)
      .join("\n");

    results.push({
      checkId: "IAM-004g",
      title: "setMetadata permission check",
      severity: "HIGH",
      status: "FAIL",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: `The following bindings grant compute.instances.setMetadata, allowing modification of instance startup scripts:\n${details}`,
      remediation: `Restrict compute admin roles. Use custom roles without setMetadata where possible:\ngcloud projects remove-iam-policy-binding ${project} --role="<ROLE>" --member="<MEMBER>"`,
      reference: "https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys#risks",
    });
  } else {
    results.push({
      checkId: "IAM-004g",
      title: "setMetadata permission check",
      severity: "HIGH",
      status: "PASS",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: "No bindings found granting compute.instances.setMetadata via known admin roles.",
      remediation: "No action required.",
    });
  }

  return results;
}
