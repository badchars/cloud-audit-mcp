import type { AzureClientFactory } from "./client.js";
import type { CheckResult } from "../types/index.js";

interface StorageArgs {
  resourceGroup?: string;
}

/**
 * STOR-001: Public blob access enabled on storage account
 * STOR-002: Container-level public access (Blob or Container)
 */
export async function checkStoragePublic(
  azure: AzureClientFactory,
  args: StorageArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const client = azure.storage();
  const subId = azure.getSubscriptionId();

  try {
    const accounts = args.resourceGroup
      ? client.storageAccounts.listByResourceGroup(args.resourceGroup)
      : client.storageAccounts.list();

    for await (const account of accounts) {
      const accountName = account.name || "unknown";
      const rg = extractResourceGroup(account.id);
      const location = account.location || "unknown";

      // STOR-001: Check allowBlobPublicAccess at account level
      if (account.allowBlobPublicAccess === true) {
        results.push({
          checkId: "STOR-001",
          title: "Public blob access enabled on storage account",
          severity: "HIGH",
          status: "FAIL",
          resource: `${subId}/storageAccounts/${accountName}`,
          region: location,
          provider: "azure",
          details: `Storage account '${accountName}' has allowBlobPublicAccess set to true. Any container in this account can be configured for anonymous public access.`,
          remediation: `az storage account update --name ${accountName} --resource-group ${rg} --allow-blob-public-access false`,
          reference:
            "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent",
        });
      } else {
        results.push({
          checkId: "STOR-001",
          title: "Public blob access enabled on storage account",
          severity: "HIGH",
          status: "PASS",
          resource: `${subId}/storageAccounts/${accountName}`,
          region: location,
          provider: "azure",
          details: `Storage account '${accountName}' has allowBlobPublicAccess disabled.`,
          remediation: "No action required.",
        });
      }

      // STOR-002: Check individual container public access levels
      if (rg) {
        try {
          const containers = client.blobContainers.list(rg, accountName);
          for await (const container of containers) {
            const containerName = container.name || "unknown";
            const publicAccess = container.publicAccess;

            if (publicAccess && publicAccess !== "None") {
              results.push({
                checkId: "STOR-002",
                title: "Container public access level is not private",
                severity: "HIGH",
                status: "FAIL",
                resource: `${subId}/storageAccounts/${accountName}/containers/${containerName}`,
                region: location,
                provider: "azure",
                details: `Container '${containerName}' in storage account '${accountName}' has public access level set to '${publicAccess}'. This allows anonymous read access to blobs${publicAccess === "Container" ? " and container metadata" : ""}.`,
                remediation: `az storage container set-permission --name ${containerName} --account-name ${accountName} --public-access off`,
                reference:
                  "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure",
              });
            } else {
              results.push({
                checkId: "STOR-002",
                title: "Container public access level is not private",
                severity: "HIGH",
                status: "PASS",
                resource: `${subId}/storageAccounts/${accountName}/containers/${containerName}`,
                region: location,
                provider: "azure",
                details: `Container '${containerName}' in storage account '${accountName}' has public access disabled.`,
                remediation: "No action required.",
              });
            }
          }
        } catch (containerErr) {
          results.push({
            checkId: "STOR-002",
            title: "Container public access level is not private",
            severity: "HIGH",
            status: "ERROR",
            resource: `${subId}/storageAccounts/${accountName}`,
            region: location,
            provider: "azure",
            details: `Failed to list containers for storage account '${accountName}': ${(containerErr as Error).message}`,
            remediation: "Ensure the identity has Storage Blob Data Reader or equivalent role.",
          });
        }
      }
    }
  } catch (err) {
    results.push({
      checkId: "STOR-001",
      title: "Public blob access enabled on storage account",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/storageAccounts`,
      region: "global",
      provider: "azure",
      details: `Failed to list storage accounts: ${(err as Error).message}`,
      remediation:
        "Ensure the identity has Reader role on the subscription and AZURE_SUBSCRIPTION_ID is set.",
    });
  }

  return results;
}

/**
 * STOR-003: Long-lived SAS tokens / shared key access
 * Checks whether shared key access is enabled (allowSharedKeyAccess).
 * Direct SAS token enumeration is not available via ARM API, but shared key
 * access being enabled is a prerequisite for SAS token generation.
 */
export async function checkStorageSas(
  azure: AzureClientFactory,
  args: StorageArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const client = azure.storage();
  const subId = azure.getSubscriptionId();

  try {
    const accounts = args.resourceGroup
      ? client.storageAccounts.listByResourceGroup(args.resourceGroup)
      : client.storageAccounts.list();

    for await (const account of accounts) {
      const accountName = account.name || "unknown";
      const location = account.location || "unknown";

      // Check if shared key access is enabled (prerequisite for SAS)
      // When allowSharedKeyAccess is null/undefined, it defaults to true
      const sharedKeyEnabled = account.allowSharedKeyAccess !== false;

      if (sharedKeyEnabled) {
        results.push({
          checkId: "STOR-003",
          title: "Shared key access enabled (SAS token generation possible)",
          severity: "MEDIUM",
          status: "FAIL",
          resource: `${subId}/storageAccounts/${accountName}`,
          region: location,
          provider: "azure",
          details: `Storage account '${accountName}' has shared key access enabled. This allows creation of SAS tokens (including long-lived ones) and direct shared key authentication. Consider disabling shared key access and using Azure AD authentication instead.`,
          remediation: `az storage account update --name ${accountName} --resource-group ${extractResourceGroup(account.id)} --allow-shared-key-access false`,
          reference:
            "https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent",
        });
      } else {
        results.push({
          checkId: "STOR-003",
          title: "Shared key access enabled (SAS token generation possible)",
          severity: "MEDIUM",
          status: "PASS",
          resource: `${subId}/storageAccounts/${accountName}`,
          region: location,
          provider: "azure",
          details: `Storage account '${accountName}' has shared key access disabled. Only Azure AD authentication is permitted.`,
          remediation: "No action required.",
        });
      }
    }
  } catch (err) {
    results.push({
      checkId: "STOR-003",
      title: "Shared key access enabled (SAS token generation possible)",
      severity: "MEDIUM",
      status: "ERROR",
      resource: `${subId}/storageAccounts`,
      region: "global",
      provider: "azure",
      details: `Failed to list storage accounts: ${(err as Error).message}`,
      remediation:
        "Ensure the identity has Reader role on the subscription.",
    });
  }

  return results;
}

function extractResourceGroup(resourceId?: string): string {
  if (!resourceId) return "unknown";
  const match = resourceId.match(/resourceGroups\/([^/]+)/i);
  return match ? match[1] : "unknown";
}
