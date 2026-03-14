import type { CheckResult } from "../types/index.js";
import type { GcpClientFactory } from "./client.js";

const SA_KEY_PATTERNS = [
  /\.json$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /service[-_]?account/i,
  /credentials/i,
  /keyfile/i,
];

const SENSITIVE_PATTERNS = [
  /\.sql$/i,
  /\.bak$/i,
  /\.env$/i,
  /\.env\.\w+$/i,
  /config\.(ya?ml|json|toml|ini)$/i,
  /\.tfstate$/i,
  /\.tfvars$/i,
  /\.htpasswd$/i,
  /\.ssh\//i,
  /id_rsa/i,
  /id_ed25519/i,
  /dump/i,
  /backup/i,
  /password/i,
  /secret/i,
  /\.jks$/i,
  /\.kdbx?$/i,
  /\.pgpass$/i,
  /kubeconfig/i,
  /\.dockercfg$/i,
];

/**
 * GCS-001: Public bucket access — check IAM policy for allUsers / allAuthenticatedUsers bindings
 * GCS-003: Sensitive files in buckets — pattern match object keys
 */
export async function checkGcsPublic(
  gcp: GcpClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const project = gcp.getProjectId();
  const storage = gcp.storage();

  let buckets: any[];
  try {
    const [bucketList] = await storage.getBuckets();
    buckets = bucketList;
  } catch (err) {
    results.push({
      checkId: "GCS-001",
      title: "Public bucket access",
      severity: "CRITICAL",
      status: "ERROR",
      resource: `gcs:${project}/*`,
      region: "global",
      provider: "gcp",
      details: `Failed to list buckets: ${(err as Error).message}`,
      remediation: "Verify that Application Default Credentials are configured and have storage.buckets.list permission.",
    });
    return results;
  }

  for (const bucket of buckets) {
    const name: string = bucket.name ?? bucket.id ?? "unknown";
    const resource = `gs://${name}`;

    // --- GCS-001: Check IAM policy for public access ---
    try {
      const [policy] = await bucket.iam.getPolicy();
      const publicBindings: string[] = [];

      for (const binding of policy.bindings ?? []) {
        const role: string = binding.role ?? "";
        const members: string[] = binding.members ?? [];

        for (const member of members) {
          if (member === "allUsers" || member === "allAuthenticatedUsers") {
            publicBindings.push(`${member} → ${role}`);
          }
        }
      }

      if (publicBindings.length > 0) {
        results.push({
          checkId: "GCS-001",
          title: "Public bucket access",
          severity: "CRITICAL",
          status: "FAIL",
          resource,
          region: bucket.metadata?.location ?? "global",
          provider: "gcp",
          details: `Bucket has public IAM bindings: ${publicBindings.join("; ")}`,
          remediation: `gcloud storage buckets remove-iam-policy-binding gs://${name} --member=allUsers --role=<ROLE>\ngcloud storage buckets remove-iam-policy-binding gs://${name} --member=allAuthenticatedUsers --role=<ROLE>`,
          reference: "https://cloud.google.com/storage/docs/access-control/iam",
        });
      } else {
        results.push({
          checkId: "GCS-001",
          title: "Public bucket access",
          severity: "CRITICAL",
          status: "PASS",
          resource,
          region: bucket.metadata?.location ?? "global",
          provider: "gcp",
          details: "No public IAM bindings (allUsers or allAuthenticatedUsers) found on the bucket.",
          remediation: "No action required.",
        });
      }
    } catch (err) {
      results.push({
        checkId: "GCS-001",
        title: "Public bucket access",
        severity: "CRITICAL",
        status: "ERROR",
        resource,
        region: bucket.metadata?.location ?? "global",
        provider: "gcp",
        details: `Failed to get IAM policy for bucket: ${(err as Error).message}`,
        remediation: "Verify IAM permissions: storage.buckets.getIamPolicy",
      });
    }
  }

  return results;
}

/**
 * GCS-002: Service account keys stored in GCS
 * GCS-003: Sensitive files in buckets (SQL dumps, backups, env files, configs)
 */
export async function checkGcsObjects(
  gcp: GcpClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const project = gcp.getProjectId();
  const storage = gcp.storage();

  let buckets: any[];
  try {
    const [bucketList] = await storage.getBuckets();
    buckets = bucketList;
  } catch (err) {
    results.push({
      checkId: "GCS-002",
      title: "SA keys in storage",
      severity: "CRITICAL",
      status: "ERROR",
      resource: `gcs:${project}/*`,
      region: "global",
      provider: "gcp",
      details: `Failed to list buckets: ${(err as Error).message}`,
      remediation: "Verify Application Default Credentials and storage.buckets.list permission.",
    });
    return results;
  }

  for (const bucket of buckets) {
    const name: string = bucket.name ?? bucket.id ?? "unknown";
    const resource = `gs://${name}`;
    const bucketRegion: string = bucket.metadata?.location ?? "global";

    const saKeyFiles: string[] = [];
    const sensitiveFiles: string[] = [];

    try {
      const [files] = await bucket.getFiles({ maxResults: 5000 });

      for (const file of files) {
        const fileName: string = file.name ?? "";

        // GCS-002: SA key file patterns
        for (const pattern of SA_KEY_PATTERNS) {
          if (pattern.test(fileName)) {
            saKeyFiles.push(fileName);
            break;
          }
        }

        // GCS-003: Sensitive file patterns
        for (const pattern of SENSITIVE_PATTERNS) {
          if (pattern.test(fileName)) {
            sensitiveFiles.push(fileName);
            break;
          }
        }
      }
    } catch (err) {
      const msg = (err as Error).message;
      // Report error for both checks and continue
      results.push({
        checkId: "GCS-002",
        title: "SA keys in storage",
        severity: "CRITICAL",
        status: "ERROR",
        resource,
        region: bucketRegion,
        provider: "gcp",
        details: `Failed to list objects in bucket: ${msg}`,
        remediation: "Verify IAM permissions: storage.objects.list",
      });
      results.push({
        checkId: "GCS-003",
        title: "Sensitive files in buckets",
        severity: "HIGH",
        status: "ERROR",
        resource,
        region: bucketRegion,
        provider: "gcp",
        details: `Failed to list objects in bucket: ${msg}`,
        remediation: "Verify IAM permissions: storage.objects.list",
      });
      continue;
    }

    // --- GCS-002 results ---
    if (saKeyFiles.length > 0) {
      const display = saKeyFiles.slice(0, 20);
      const extra = saKeyFiles.length > 20 ? ` ... and ${saKeyFiles.length - 20} more` : "";
      results.push({
        checkId: "GCS-002",
        title: "SA keys in storage",
        severity: "CRITICAL",
        status: "FAIL",
        resource,
        region: bucketRegion,
        provider: "gcp",
        details: `Found ${saKeyFiles.length} potential service account key file(s): ${display.join(", ")}${extra}`,
        remediation: `Remove SA key files from GCS immediately. Use Workload Identity Federation instead of exported keys.\ngcloud storage rm gs://${name}/<KEY_FILE>`,
        reference: "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",
      });
    } else {
      results.push({
        checkId: "GCS-002",
        title: "SA keys in storage",
        severity: "CRITICAL",
        status: "PASS",
        resource,
        region: bucketRegion,
        provider: "gcp",
        details: "No service account key file patterns detected in object names.",
        remediation: "No action required.",
      });
    }

    // --- GCS-003 results ---
    if (sensitiveFiles.length > 0) {
      const display = sensitiveFiles.slice(0, 20);
      const extra = sensitiveFiles.length > 20 ? ` ... and ${sensitiveFiles.length - 20} more` : "";
      results.push({
        checkId: "GCS-003",
        title: "Sensitive files in buckets",
        severity: "HIGH",
        status: "FAIL",
        resource,
        region: bucketRegion,
        provider: "gcp",
        details: `Found ${sensitiveFiles.length} potentially sensitive file(s): ${display.join(", ")}${extra}`,
        remediation: "Review and remove sensitive files from GCS. Use Secret Manager for credentials and sensitive configuration.",
        reference: "https://cloud.google.com/secret-manager/docs/overview",
      });
    } else {
      results.push({
        checkId: "GCS-003",
        title: "Sensitive files in buckets",
        severity: "HIGH",
        status: "PASS",
        resource,
        region: bucketRegion,
        provider: "gcp",
        details: "No sensitive file patterns detected in object names.",
        remediation: "No action required.",
      });
    }
  }

  return results;
}
