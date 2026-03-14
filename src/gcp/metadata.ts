import type { CheckResult } from "../types/index.js";
import type { GcpClientFactory } from "./client.js";

const SECRET_PATTERNS = [
  /password\s*[:=]\s*\S+/i,
  /secret\s*[:=]\s*\S+/i,
  /api[_-]?key\s*[:=]\s*\S+/i,
  /token\s*[:=]\s*\S+/i,
  /private[_-]?key/i,
  /BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY/i,
  /mysql\s+.*-p\S+/i,
  /curl\s+.*-u\s+\S+:\S+/i,
  /export\s+(AWS_SECRET|DB_PASS|API_KEY|SECRET)/i,
  /AKIA[0-9A-Z]{16}/i,
];

const CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

/**
 * META-001: Startup script secrets — check instance metadata startup-script for hardcoded secrets
 * META-002: Instance with cloud-platform scope — overly broad OAuth scope
 * META-003: Metadata concealment not enabled — workload identity / metadata protection
 */
export async function checkMetadata(
  gcp: GcpClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const project = gcp.getProjectId();
  const instancesClient = gcp.instances();

  try {
    // aggregatedList returns instances across all zones in one call
    const aggListIterable = instancesClient.aggregatedListAsync({
      project,
    });

    let totalInstances = 0;

    for await (const [zonePath, scopedList] of aggListIterable) {
      const instances = scopedList.instances ?? [];
      if (instances.length === 0) continue;

      // Extract zone name from "zones/us-central1-a" format
      const zone = zonePath.replace(/^zones\//, "");

      for (const instance of instances) {
        totalInstances++;
        const instanceName = instance.name ?? "unknown";
        const resource = `projects/${project}/zones/${zone}/instances/${instanceName}`;
        const selfLink = instance.selfLink ?? resource;

        // --- META-001: Check startup-script for hardcoded secrets ---
        const metadataItems = instance.metadata?.items ?? [];
        const startupScripts: { key: string; value: string }[] = [];

        for (const item of metadataItems) {
          const key = item.key ?? "";
          if (
            key === "startup-script" ||
            key === "startup-script-url" ||
            key === "windows-startup-script-ps1" ||
            key === "windows-startup-script-cmd"
          ) {
            startupScripts.push({ key, value: item.value ?? "" });
          }
        }

        if (startupScripts.length > 0) {
          const secretMatches: string[] = [];

          for (const script of startupScripts) {
            // Skip URL references — we cannot fetch and scan them
            if (script.key === "startup-script-url") continue;

            for (const pattern of SECRET_PATTERNS) {
              const match = script.value.match(pattern);
              if (match) {
                // Redact the actual value, only show the pattern matched
                secretMatches.push(`${script.key}: matched pattern "${pattern.source}"`);
                break; // one match per script is enough
              }
            }
          }

          if (secretMatches.length > 0) {
            results.push({
              checkId: "META-001",
              title: "Startup script secrets",
              severity: "HIGH",
              status: "FAIL",
              resource: selfLink,
              region: zone,
              provider: "gcp",
              details: `Instance startup script contains potential hardcoded secrets: ${secretMatches.join("; ")}`,
              remediation: `Move secrets to Secret Manager and reference them in startup scripts.\ngcloud secrets create <SECRET_NAME> --data-file=<FILE>\nAccess in script: gcloud secrets versions access latest --secret=<SECRET_NAME>`,
              reference: "https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets",
            });
          } else {
            results.push({
              checkId: "META-001",
              title: "Startup script secrets",
              severity: "HIGH",
              status: "PASS",
              resource: selfLink,
              region: zone,
              provider: "gcp",
              details: "Startup script present but no hardcoded secret patterns detected.",
              remediation: "No action required.",
            });
          }
        }
        // If no startup script, no finding to report for META-001

        // --- META-002: Instance with cloud-platform scope ---
        const serviceAccounts = instance.serviceAccounts ?? [];
        let hasCloudPlatformScope = false;

        for (const sa of serviceAccounts) {
          const scopes = sa.scopes ?? [];
          if (scopes.includes(CLOUD_PLATFORM_SCOPE)) {
            hasCloudPlatformScope = true;
            results.push({
              checkId: "META-002",
              title: "Instance with cloud-platform scope",
              severity: "HIGH",
              status: "FAIL",
              resource: selfLink,
              region: zone,
              provider: "gcp",
              details: `Instance uses service account "${sa.email}" with the overly broad "cloud-platform" scope, granting access to all GCP APIs.`,
              remediation: `Restrict OAuth scopes to only the APIs needed. Stop the instance, update scopes, and restart:\ngcloud compute instances set-service-account ${instanceName} --zone=${zone} --scopes=storage-ro,logging-write,monitoring`,
              reference: "https://cloud.google.com/compute/docs/access/service-accounts#accesscopesiam",
            });
          }
        }

        if (!hasCloudPlatformScope && serviceAccounts.length > 0) {
          results.push({
            checkId: "META-002",
            title: "Instance with cloud-platform scope",
            severity: "HIGH",
            status: "PASS",
            resource: selfLink,
            region: zone,
            provider: "gcp",
            details: "Instance service account does not use the overly broad cloud-platform scope.",
            remediation: "No action required.",
          });
        }

        // --- META-003: Metadata concealment / Workload Identity ---
        // Check if workload identity metadata is enabled (GKE nodes have this)
        // For regular VMs, check if the metadata server is shielded
        const shieldedConfig = instance.shieldedInstanceConfig;
        const hasSecureBoot = shieldedConfig?.enableSecureBoot === true;
        const hasVtpm = shieldedConfig?.enableVtpm === true;
        const hasIntegrityMonitoring = shieldedConfig?.enableIntegrityMonitoring === true;

        // Check for metadata concealment via instance labels or metadata
        const hasMetadataConcealment = metadataItems.some(
          (item) => item.key === "workload-identity" || item.key === "disable-legacy-endpoints",
        );
        const legacyEndpointsDisabled = metadataItems.some(
          (item) => item.key === "disable-legacy-endpoints" && item.value === "true",
        );

        if (!legacyEndpointsDisabled) {
          results.push({
            checkId: "META-003",
            title: "Legacy metadata endpoint enabled",
            severity: "MEDIUM",
            status: "FAIL",
            resource: selfLink,
            region: zone,
            provider: "gcp",
            details: `Instance does not have legacy metadata endpoint (v1beta1) disabled. Legacy endpoint does not enforce metadata headers, making it easier to exploit SSRF for metadata access.${!hasSecureBoot ? " Secure Boot is also not enabled." : ""}`,
            remediation: `Disable legacy metadata endpoints:\ngcloud compute instances add-metadata ${instanceName} --zone=${zone} --metadata=disable-legacy-endpoints=true\n\nFor new instances, use --metadata=disable-legacy-endpoints=true at creation time.`,
            reference: "https://cloud.google.com/compute/docs/metadata/overview#legacy_metadata_server_endpoints",
          });
        } else {
          results.push({
            checkId: "META-003",
            title: "Legacy metadata endpoint enabled",
            severity: "MEDIUM",
            status: "PASS",
            resource: selfLink,
            region: zone,
            provider: "gcp",
            details: "Legacy metadata endpoint is disabled. Instance uses v1 metadata endpoint with required headers.",
            remediation: "No action required.",
          });
        }
      }
    }

    if (totalInstances === 0) {
      results.push({
        checkId: "META-001",
        title: "Startup script secrets",
        severity: "HIGH",
        status: "NOT_APPLICABLE",
        resource: `projects/${project}`,
        region: "global",
        provider: "gcp",
        details: "No Compute Engine instances found in the project.",
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "META-001",
      title: "Startup script secrets",
      severity: "HIGH",
      status: "ERROR",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: `Failed to list instances: ${(err as Error).message}`,
      remediation: "Verify Application Default Credentials and compute.instances.list permission.",
    });
  }

  return results;
}
