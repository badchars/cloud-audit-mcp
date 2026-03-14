import type { CheckResult } from "../types/index.js";
import type { GcpClientFactory } from "./client.js";

// GCR bucket naming patterns
// Legacy GCR: artifacts.<PROJECT_ID>.appspot.com
// Regional GCR: <REGION>.artifacts.<PROJECT_ID>.appspot.com
// Artifact Registry uses different storage, but GCR still uses GCS buckets
const GCR_BUCKET_PATTERNS = [
  /^artifacts\..+\.appspot\.com$/,
  /^[a-z]+-artifacts\..+\.appspot\.com$/, // regional: us.artifacts, eu.artifacts, asia.artifacts
  /^[a-z]+\.artifacts\..+\.appspot\.com$/,
];

// Suspicious image patterns
const SUSPICIOUS_IMAGE_PATTERNS = [
  /cryptomin/i,
  /xmrig/i,
  /monero/i,
  /backdoor/i,
  /reverse.?shell/i,
  /\.\.\//, // path traversal
  /meterpreter/i,
  /cobalt/i,
  /implant/i,
];

/**
 * GCR-001: Audit Google Container Registry for unexpected/hidden images
 *
 * GCR stores images as layers in GCS buckets named artifacts.<PROJECT>.appspot.com.
 * This check:
 * 1. Identifies GCR buckets in the project
 * 2. Lists container image manifests stored in them
 * 3. Flags suspicious image names that may indicate compromise
 * 4. Reports public access on GCR buckets (image pull without auth)
 */
export async function checkGcr(
  gcp: GcpClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const project = gcp.getProjectId();
  const storage = gcp.storage();

  let allBuckets: any[];
  try {
    const [bucketList] = await storage.getBuckets();
    allBuckets = bucketList;
  } catch (err) {
    results.push({
      checkId: "GCR-001",
      title: "Container Registry audit",
      severity: "HIGH",
      status: "ERROR",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: `Failed to list buckets: ${(err as Error).message}`,
      remediation: "Verify Application Default Credentials and storage.buckets.list permission.",
    });
    return results;
  }

  // Find GCR buckets
  const gcrBuckets = allBuckets.filter((bucket) => {
    const name: string = bucket.name ?? bucket.id ?? "";
    return GCR_BUCKET_PATTERNS.some((pattern) => pattern.test(name));
  });

  if (gcrBuckets.length === 0) {
    results.push({
      checkId: "GCR-001",
      title: "Container Registry audit",
      severity: "HIGH",
      status: "NOT_APPLICABLE",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: "No GCR (Container Registry) buckets found in the project. The project may use Artifact Registry instead, or has no container images.",
      remediation: "If using Artifact Registry, run separate Artifact Registry checks. Consider migrating from GCR to Artifact Registry.",
    });
    return results;
  }

  for (const bucket of gcrBuckets) {
    const bucketName: string = bucket.name ?? bucket.id ?? "unknown";
    const resource = `gs://${bucketName}`;
    const bucketRegion: string = bucket.metadata?.location ?? "global";

    // --- Check public access on GCR bucket ---
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
          checkId: "GCR-001",
          title: "Container Registry bucket publicly accessible",
          severity: "CRITICAL",
          status: "FAIL",
          resource,
          region: bucketRegion,
          provider: "gcp",
          details: `GCR bucket is publicly accessible. Anyone can pull container images. Bindings: ${publicBindings.join("; ")}`,
          remediation: `Remove public access from the GCR bucket:\ngcloud storage buckets remove-iam-policy-binding gs://${bucketName} --member=allUsers --role=<ROLE>\ngcloud storage buckets remove-iam-policy-binding gs://${bucketName} --member=allAuthenticatedUsers --role=<ROLE>`,
          reference: "https://cloud.google.com/container-registry/docs/access-control",
        });
      }
    } catch (err) {
      // Non-fatal, continue with object listing
      results.push({
        checkId: "GCR-001",
        title: "Container Registry bucket IAM check",
        severity: "CRITICAL",
        status: "ERROR",
        resource,
        region: bucketRegion,
        provider: "gcp",
        details: `Failed to check IAM policy on GCR bucket: ${(err as Error).message}`,
        remediation: "Verify permissions: storage.buckets.getIamPolicy",
      });
    }

    // --- List images in the GCR bucket ---
    // GCR stores images under containers/images/ prefix
    // Manifests are at containers/images/sha256:<hash>
    // Image names are in containers/repositories/ as directory-like prefixes
    try {
      const imageNames = new Set<string>();
      const suspiciousImages: string[] = [];

      // List objects with the repositories prefix to find image names
      const [files] = await bucket.getFiles({
        prefix: "containers/repositories/",
        maxResults: 5000,
        delimiter: "/",
      });

      // Also check top-level objects to find any unexpected content
      const [topFiles] = await bucket.getFiles({
        maxResults: 1000,
      });

      // Extract image repository names from file paths
      // Format: containers/repositories/<image_name>/...
      for (const file of files) {
        const path: string = file.name ?? "";
        const parts = path.split("/");
        if (parts.length >= 4) {
          // parts[0] = "containers", parts[1] = "repositories", parts[2+] = image name segments
          const imageName = parts.slice(2, -1).join("/");
          if (imageName) {
            imageNames.add(imageName);
          }
        }
      }

      // If no repository files found, check raw file listing for image layers
      if (imageNames.size === 0 && topFiles.length > 0) {
        // Count total objects to understand bucket usage
        const hasContainerContent = topFiles.some(
          (f: any) => (f.name ?? "").startsWith("containers/"),
        );

        if (hasContainerContent) {
          results.push({
            checkId: "GCR-001",
            title: "Container Registry images found",
            severity: "HIGH",
            status: "FAIL",
            resource,
            region: bucketRegion,
            provider: "gcp",
            details: `GCR bucket contains container data but image names could not be enumerated from the repository index. Total objects found: ${topFiles.length}. Manual review recommended.`,
            remediation: `List images using:\ngcloud container images list --repository=gcr.io/${project}\ngcloud container images list --repository=us.gcr.io/${project}`,
            reference: "https://cloud.google.com/container-registry/docs/managing",
          });
        } else {
          results.push({
            checkId: "GCR-001",
            title: "Container Registry bucket with non-container content",
            severity: "MEDIUM",
            status: "FAIL",
            resource,
            region: bucketRegion,
            provider: "gcp",
            details: `GCR bucket exists but contains non-container content (${topFiles.length} objects). This may indicate misuse of the GCR bucket for general storage.`,
            remediation: "Review bucket contents and remove non-container objects. GCR buckets should only contain container image data.",
          });
        }
        continue;
      }

      // Check for suspicious image names
      for (const imageName of imageNames) {
        for (const pattern of SUSPICIOUS_IMAGE_PATTERNS) {
          if (pattern.test(imageName)) {
            suspiciousImages.push(imageName);
            break;
          }
        }
      }

      if (suspiciousImages.length > 0) {
        results.push({
          checkId: "GCR-001",
          title: "Suspicious container images detected",
          severity: "CRITICAL",
          status: "FAIL",
          resource,
          region: bucketRegion,
          provider: "gcp",
          details: `Found ${suspiciousImages.length} suspicious image(s) in GCR: ${suspiciousImages.join(", ")}. These names match patterns commonly associated with malicious containers.`,
          remediation: `Investigate these images immediately:\ngcloud container images describe gcr.io/${project}/<IMAGE_NAME>\ngcloud container images list-tags gcr.io/${project}/<IMAGE_NAME>\n\nDelete unauthorized images:\ngcloud container images delete gcr.io/${project}/<IMAGE_NAME>:<TAG> --force-delete-tags`,
          reference: "https://cloud.google.com/container-registry/docs/managing",
        });
      }

      // Report total image count
      if (imageNames.size > 0) {
        const imageList = Array.from(imageNames).slice(0, 30);
        const extra = imageNames.size > 30 ? ` ... and ${imageNames.size - 30} more` : "";
        const hasSuspicious = suspiciousImages.length > 0;

        if (!hasSuspicious) {
          results.push({
            checkId: "GCR-001",
            title: "Container Registry images",
            severity: "HIGH",
            status: "PASS",
            resource,
            region: bucketRegion,
            provider: "gcp",
            details: `Found ${imageNames.size} image(s) in GCR bucket. No suspicious patterns detected.\nImages: ${imageList.join(", ")}${extra}`,
            remediation: "Periodically review container images and remove unused ones. Consider migrating to Artifact Registry for vulnerability scanning.",
          });
        }
      }
    } catch (err) {
      results.push({
        checkId: "GCR-001",
        title: "Container Registry audit",
        severity: "HIGH",
        status: "ERROR",
        resource,
        region: bucketRegion,
        provider: "gcp",
        details: `Failed to list objects in GCR bucket: ${(err as Error).message}`,
        remediation: "Verify IAM permissions: storage.objects.list on the GCR bucket.",
      });
    }
  }

  return results;
}
