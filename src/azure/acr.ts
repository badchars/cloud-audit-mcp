import type { AzureClientFactory } from "./client.js";
import type { CheckResult } from "../types/index.js";

interface AcrArgs {
  resourceGroup?: string;
}

/**
 * ACR-001: Admin user enabled on container registry
 * ACR-002: Secrets in container images (stub - requires docker pull)
 */
export async function checkAcr(
  azure: AzureClientFactory,
  args: AcrArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const client = azure.containerRegistry();
  const subId = azure.getSubscriptionId();

  try {
    const registries = args.resourceGroup
      ? client.registries.listByResourceGroup(args.resourceGroup)
      : client.registries.list();

    for await (const registry of registries) {
      const registryName = registry.name || "unknown";
      const location = registry.location || "unknown";
      const rg = extractResourceGroup(registry.id);

      // ACR-001: Check if admin user is enabled
      if (registry.adminUserEnabled === true) {
        results.push({
          checkId: "ACR-001",
          title: "Admin user enabled on container registry",
          severity: "HIGH",
          status: "FAIL",
          resource: `${subId}/resourceGroups/${rg}/registries/${registryName}`,
          region: location,
          provider: "azure",
          details:
            `Container registry '${registryName}' has admin user enabled. The admin account ` +
            `provides unrestricted push/pull access with a shared password. This password can ` +
            `be retrieved by anyone with sufficient Azure RBAC permissions and is difficult to ` +
            `audit or revoke per-consumer. Admin credentials are often embedded in CI/CD ` +
            `pipelines, Docker configs, or Kubernetes secrets, increasing exposure risk.`,
          remediation:
            `Disable admin user and use Azure AD-based authentication:\n` +
            `az acr update --name ${registryName} --resource-group ${rg} --admin-enabled false\n\n` +
            `Use managed identity or service principal for pull access:\n` +
            `az acr credential renew --name ${registryName} --resource-group ${rg} --password-name password\n` +
            `az role assignment create --assignee <principal-id> --role AcrPull --scope /subscriptions/${subId}/resourceGroups/${rg}/providers/Microsoft.ContainerRegistry/registries/${registryName}`,
          reference:
            "https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication",
        });
      } else {
        results.push({
          checkId: "ACR-001",
          title: "Admin user enabled on container registry",
          severity: "HIGH",
          status: "PASS",
          resource: `${subId}/resourceGroups/${rg}/registries/${registryName}`,
          region: location,
          provider: "azure",
          details:
            `Container registry '${registryName}' has admin user disabled. ` +
            `Authentication must use Azure AD-based mechanisms (service principal, managed identity, or individual login).`,
          remediation: "No action required.",
        });
      }

      // ACR-002: Secrets in container images (stub)
      // Full implementation would require:
      // 1. Listing repositories and tags: client.repositories.list()
      // 2. Pulling image layers via Docker Registry v2 API
      // 3. Scanning layer contents for credential patterns
      // 4. Using tools like Trivy, Grype, or Snyk for deep scanning
      // This is not feasible via ARM API alone.
      results.push({
        checkId: "ACR-002",
        title: "Secrets in container images",
        severity: "HIGH",
        status: "NOT_APPLICABLE",
        resource: `${subId}/resourceGroups/${rg}/registries/${registryName}`,
        region: location,
        provider: "azure",
        details:
          `Scanning container images for embedded secrets requires pulling and inspecting ` +
          `image layers, which cannot be done through the Azure ARM API. To detect secrets ` +
          `in container images:\n` +
          `  1. Enable Azure Defender for Container Registries (Microsoft Defender for Cloud)\n` +
          `  2. Use container scanning tools (Trivy, Grype, Snyk) in CI/CD pipelines\n` +
          `  3. Scan images with: trivy image ${registryName}.azurecr.io/<repo>:<tag>\n` +
          `Registry '${registryName}' has ${registry.sku?.name || "unknown"} SKU.`,
        remediation:
          `Enable Microsoft Defender for Container Registries:\n` +
          `az security pricing create --name ContainerRegistry --tier Standard\n\n` +
          `Or scan images manually:\n` +
          `az acr login --name ${registryName}\n` +
          `trivy image ${registryName}.azurecr.io/<repository>:<tag>`,
        reference:
          "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction",
      });
    }
  } catch (err) {
    results.push({
      checkId: "ACR-001",
      title: "Admin user enabled on container registry",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/registries`,
      region: "global",
      provider: "azure",
      details: `Failed to list container registries: ${(err as Error).message}`,
      remediation: "Ensure the identity has Reader role on the subscription.",
    });
  }

  return results;
}

function extractResourceGroup(resourceId?: string): string {
  if (!resourceId) return "unknown";
  const match = resourceId.match(/resourceGroups\/([^/]+)/i);
  return match ? match[1] : "unknown";
}
