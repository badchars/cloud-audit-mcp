import type { AzureClientFactory } from "./client.js";
import type { CheckResult } from "../types/index.js";

interface KeyvaultArgs {
  resourceGroup?: string;
}

// Permissions that are considered overly broad
const OVERLY_BROAD_KEY_PERMISSIONS = ["all"];
const OVERLY_BROAD_SECRET_PERMISSIONS = ["all"];
const OVERLY_BROAD_CERTIFICATE_PERMISSIONS = ["all"];

// Dangerous individual permissions that should be monitored
const DANGEROUS_SECRET_PERMISSIONS = ["get", "list", "set", "delete", "purge", "backup", "restore"];
const DANGEROUS_KEY_PERMISSIONS = ["get", "list", "create", "delete", "purge", "sign", "decrypt", "unwrapKey", "import"];

/**
 * KV-001: Overly permissive access policies
 * KV-002: Network access not restricted
 */
export async function checkKeyvault(
  azure: AzureClientFactory,
  args: KeyvaultArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const client = azure.keyVault();
  const subId = azure.getSubscriptionId();

  try {
    const resourceGroups = await getResourceGroups(azure, args.resourceGroup);

    for (const rg of resourceGroups) {
      try {
        const vaults = client.vaults.listByResourceGroup(rg);

        for await (const vault of vaults) {
          const vaultName = vault.name || "unknown";
          const location = vault.location || "unknown";

          // KV-001: Check access policies for overly broad permissions
          checkAccessPolicies(vault, rg, vaultName, location, subId, results);

          // KV-002: Check network ACLs
          checkNetworkAcls(vault, rg, vaultName, location, subId, results);
        }
      } catch (rgErr) {
        const errMsg = (rgErr as Error).message || "";
        if (!errMsg.includes("not found") && !errMsg.includes("NoRegisteredProviderFound")) {
          results.push({
            checkId: "KV-001",
            title: "Overly permissive Key Vault access policies",
            severity: "HIGH",
            status: "ERROR",
            resource: `${subId}/resourceGroups/${rg}/vaults`,
            region: "global",
            provider: "azure",
            details: `Failed to list Key Vaults in resource group '${rg}': ${errMsg}`,
            remediation: "Ensure the identity has Key Vault Reader role.",
          });
        }
      }
    }
  } catch (err) {
    results.push({
      checkId: "KV-001",
      title: "Overly permissive Key Vault access policies",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/vaults`,
      region: "global",
      provider: "azure",
      details: `Failed to enumerate Key Vaults: ${(err as Error).message}`,
      remediation: "Ensure the identity has Reader role on the subscription.",
    });
  }

  return results;
}

function checkAccessPolicies(
  vault: any,
  rg: string,
  vaultName: string,
  location: string,
  subId: string,
  results: CheckResult[],
): void {
  const properties = vault.properties;
  if (!properties) return;

  // If using RBAC, access policies are not used
  if (properties.enableRbacAuthorization === true) {
    results.push({
      checkId: "KV-001",
      title: "Overly permissive Key Vault access policies",
      severity: "HIGH",
      status: "PASS",
      resource: `${subId}/resourceGroups/${rg}/vaults/${vaultName}`,
      region: location,
      provider: "azure",
      details:
        `Key Vault '${vaultName}' uses Azure RBAC for authorization instead of access policies. ` +
        `RBAC provides more granular control and is the recommended authorization model.`,
      remediation: "No action required.",
    });
    return;
  }

  const accessPolicies = properties.accessPolicies || [];
  const overlyPermissive: string[] = [];

  for (const policy of accessPolicies) {
    const objectId = policy.objectId || "unknown";
    const tenantId = policy.tenantId || "unknown";
    const issues: string[] = [];

    // Check key permissions
    const keyPerms: string[] = policy.permissions?.keys || [];
    if (keyPerms.some((p: string) => OVERLY_BROAD_KEY_PERMISSIONS.includes(p.toLowerCase()))) {
      issues.push(`keys: ALL permissions granted`);
    } else {
      const dangerousKeys = keyPerms.filter((p: string) =>
        DANGEROUS_KEY_PERMISSIONS.includes(p.toLowerCase()),
      );
      if (dangerousKeys.length >= 6) {
        issues.push(`keys: ${dangerousKeys.length} permissions (${dangerousKeys.join(", ")})`);
      }
    }

    // Check secret permissions
    const secretPerms: string[] = policy.permissions?.secrets || [];
    if (secretPerms.some((p: string) => OVERLY_BROAD_SECRET_PERMISSIONS.includes(p.toLowerCase()))) {
      issues.push(`secrets: ALL permissions granted`);
    } else {
      const dangerousSecrets = secretPerms.filter((p: string) =>
        DANGEROUS_SECRET_PERMISSIONS.includes(p.toLowerCase()),
      );
      if (dangerousSecrets.length >= 5) {
        issues.push(`secrets: ${dangerousSecrets.length} permissions (${dangerousSecrets.join(", ")})`);
      }
    }

    // Check certificate permissions
    const certPerms: string[] = policy.permissions?.certificates || [];
    if (certPerms.some((p: string) => OVERLY_BROAD_CERTIFICATE_PERMISSIONS.includes(p.toLowerCase()))) {
      issues.push(`certificates: ALL permissions granted`);
    }

    if (issues.length > 0) {
      overlyPermissive.push(
        `Principal ${objectId} (tenant: ${tenantId}): ${issues.join("; ")}`,
      );
    }
  }

  if (overlyPermissive.length > 0) {
    results.push({
      checkId: "KV-001",
      title: "Overly permissive Key Vault access policies",
      severity: "HIGH",
      status: "FAIL",
      resource: `${subId}/resourceGroups/${rg}/vaults/${vaultName}`,
      region: location,
      provider: "azure",
      details:
        `Key Vault '${vaultName}' has overly permissive access policies:\n` +
        overlyPermissive.map((p) => `  - ${p}`).join("\n") +
        `\n\nTotal access policies: ${accessPolicies.length}. ` +
        `Consider migrating to Azure RBAC for more granular control.`,
      remediation:
        `1. Enable RBAC authorization (recommended):\n` +
        `   az keyvault update --name ${vaultName} --resource-group ${rg} --enable-rbac-authorization true\n\n` +
        `2. Or restrict access policies to minimum required permissions:\n` +
        `   az keyvault set-policy --name ${vaultName} --resource-group ${rg} ` +
        `--object-id <principal-id> --secret-permissions get list`,
      reference:
        "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide",
    });
  } else if (accessPolicies.length > 0) {
    results.push({
      checkId: "KV-001",
      title: "Overly permissive Key Vault access policies",
      severity: "HIGH",
      status: "PASS",
      resource: `${subId}/resourceGroups/${rg}/vaults/${vaultName}`,
      region: location,
      provider: "azure",
      details:
        `Key Vault '${vaultName}' has ${accessPolicies.length} access policies, ` +
        `none of which appear overly permissive. Consider migrating to Azure RBAC ` +
        `for more granular control.`,
      remediation: "No action required. Consider migrating to Azure RBAC.",
    });
  } else {
    results.push({
      checkId: "KV-001",
      title: "Overly permissive Key Vault access policies",
      severity: "HIGH",
      status: "PASS",
      resource: `${subId}/resourceGroups/${rg}/vaults/${vaultName}`,
      region: location,
      provider: "azure",
      details: `Key Vault '${vaultName}' has no access policies configured.`,
      remediation: "No action required.",
    });
  }
}

function checkNetworkAcls(
  vault: any,
  rg: string,
  vaultName: string,
  location: string,
  subId: string,
  results: CheckResult[],
): void {
  const properties = vault.properties;
  if (!properties) return;

  const networkAcls = properties.networkAcls;
  const defaultAction = networkAcls?.defaultAction || "Allow";

  if (defaultAction === "Allow") {
    results.push({
      checkId: "KV-002",
      title: "Key Vault network access not restricted",
      severity: "MEDIUM",
      status: "FAIL",
      resource: `${subId}/resourceGroups/${rg}/vaults/${vaultName}`,
      region: location,
      provider: "azure",
      details:
        `Key Vault '${vaultName}' has network ACL default action set to 'Allow'. ` +
        `This means the vault is accessible from all networks including the public internet. ` +
        `Any authenticated principal can reach the vault's data plane from any IP address.`,
      remediation:
        `Restrict network access to specific VNets and IPs:\n` +
        `az keyvault update --name ${vaultName} --resource-group ${rg} --default-action Deny\n` +
        `az keyvault network-rule add --name ${vaultName} --resource-group ${rg} ` +
        `--vnet-name <vnet> --subnet <subnet>\n` +
        `az keyvault network-rule add --name ${vaultName} --resource-group ${rg} ` +
        `--ip-address <your-ip>/32`,
      reference:
        "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
    });
  } else {
    const ipRules = networkAcls?.ipRules || [];
    const vnetRules = networkAcls?.virtualNetworkRules || [];

    results.push({
      checkId: "KV-002",
      title: "Key Vault network access not restricted",
      severity: "MEDIUM",
      status: "PASS",
      resource: `${subId}/resourceGroups/${rg}/vaults/${vaultName}`,
      region: location,
      provider: "azure",
      details:
        `Key Vault '${vaultName}' has network ACL default action set to 'Deny'. ` +
        `Access is restricted to ${ipRules.length} IP rule(s) and ${vnetRules.length} VNet rule(s).`,
      remediation: "No action required.",
    });
  }
}

async function getResourceGroups(
  azure: AzureClientFactory,
  specificRg?: string,
): Promise<string[]> {
  if (specificRg) return [specificRg];

  const rgs: string[] = [];
  const resourceClient = azure.resources();
  for await (const rg of resourceClient.resourceGroups.list()) {
    if (rg.name) rgs.push(rg.name);
  }
  return rgs;
}
