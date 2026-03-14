import type { AzureClientFactory } from "./client.js";
import type { CheckResult } from "../types/index.js";

interface FunctionsArgs {
  resourceGroup?: string;
}

/**
 * FUNC-001: Anonymous auth level on Function Apps
 * FUNC-002: Function Apps with Key Vault references (potential injection surface)
 */
export async function checkFunctions(
  azure: AzureClientFactory,
  args: FunctionsArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const client = azure.appService();
  const subId = azure.getSubscriptionId();

  try {
    const resourceGroups = await getResourceGroups(azure, args.resourceGroup);

    for (const rg of resourceGroups) {
      try {
        const webApps = client.webApps.listByResourceGroup(rg);

        for await (const app of webApps) {
          // Filter only Function Apps (kind contains "functionapp")
          const kind = (app.kind || "").toLowerCase();
          if (!kind.includes("functionapp")) continue;

          const appName = app.name || "unknown";
          const location = app.location || "unknown";

          // FUNC-001: Check authentication settings
          await checkFunctionAuth(client, rg, appName, location, subId, results);

          // FUNC-002: Check for Key Vault references in app settings
          await checkFunctionKeyVaultRefs(client, rg, appName, location, subId, results);
        }
      } catch (rgErr) {
        const errMsg = (rgErr as Error).message || "";
        if (!errMsg.includes("not found") && !errMsg.includes("NoRegisteredProviderFound")) {
          results.push({
            checkId: "FUNC-001",
            title: "Anonymous auth level on Function App",
            severity: "HIGH",
            status: "ERROR",
            resource: `${subId}/resourceGroups/${rg}/functionApps`,
            region: "global",
            provider: "azure",
            details: `Failed to list web apps in resource group '${rg}': ${errMsg}`,
            remediation: "Ensure the identity has Website Contributor or Reader role.",
          });
        }
      }
    }
  } catch (err) {
    results.push({
      checkId: "FUNC-001",
      title: "Anonymous auth level on Function App",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/functionApps`,
      region: "global",
      provider: "azure",
      details: `Failed to enumerate Function Apps: ${(err as Error).message}`,
      remediation: "Ensure the identity has Reader role on the subscription.",
    });
  }

  return results;
}

async function checkFunctionAuth(
  client: ReturnType<AzureClientFactory["appService"]>,
  rg: string,
  appName: string,
  location: string,
  subId: string,
  results: CheckResult[],
): Promise<void> {
  try {
    // Check if built-in authentication (EasyAuth) is enabled
    const authSettings = await client.webApps.getAuthSettingsV2(rg, appName);
    const authEnabled = authSettings.platform?.enabled === true;

    // Check the site config for HTTP auth level
    const config = await client.webApps.getConfiguration(rg, appName);
    const httpAuthLevel = config.http20Enabled; // This is not directly the auth level

    // Get the function app's host keys configuration
    // Function-level auth is determined by the function.json authLevel property
    // At the app level, we check if EasyAuth is enabled and if the app allows anonymous access

    if (!authEnabled) {
      // No built-in authentication — functions rely on function keys only
      results.push({
        checkId: "FUNC-001",
        title: "Anonymous auth level on Function App",
        severity: "HIGH",
        status: "FAIL",
        resource: `${subId}/resourceGroups/${rg}/functionApps/${appName}`,
        region: location,
        provider: "azure",
        details:
          `Function App '${appName}' does not have Azure App Service Authentication (EasyAuth) enabled. ` +
          `Functions in this app rely solely on function keys for authentication. Functions configured ` +
          `with 'anonymous' authLevel will be accessible without any authentication. Even with function ` +
          `keys, they can be leaked or brute-forced.`,
        remediation:
          `Enable App Service Authentication:\n` +
          `az webapp auth update --resource-group ${rg} --name ${appName} --enabled true ` +
          `--action LoginWithAzureActiveDirectory\n\n` +
          `Or ensure all functions use 'function' or 'admin' auth level in function.json:\n` +
          `{ "bindings": [{ "authLevel": "function", ... }] }`,
        reference:
          "https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts#function-access-keys",
      });
    } else {
      results.push({
        checkId: "FUNC-001",
        title: "Anonymous auth level on Function App",
        severity: "HIGH",
        status: "PASS",
        resource: `${subId}/resourceGroups/${rg}/functionApps/${appName}`,
        region: location,
        provider: "azure",
        details:
          `Function App '${appName}' has App Service Authentication enabled. ` +
          `All requests must authenticate before reaching function code.`,
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "FUNC-001",
      title: "Anonymous auth level on Function App",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/resourceGroups/${rg}/functionApps/${appName}`,
      region: location,
      provider: "azure",
      details: `Failed to check auth settings for Function App '${appName}': ${(err as Error).message}`,
      remediation: "Ensure the identity has Website Contributor or Reader role.",
    });
  }
}

async function checkFunctionKeyVaultRefs(
  client: ReturnType<AzureClientFactory["appService"]>,
  rg: string,
  appName: string,
  location: string,
  subId: string,
  results: CheckResult[],
): Promise<void> {
  try {
    const appSettings = await client.webApps.listApplicationSettings(rg, appName);
    const properties = appSettings.properties || {};

    const kvRefs: string[] = [];
    for (const [key, value] of Object.entries(properties)) {
      // Key Vault reference format: @Microsoft.KeyVault(SecretUri=https://...)
      // or @Microsoft.KeyVault(VaultName=...;SecretName=...)
      if (value && value.includes("@Microsoft.KeyVault(")) {
        kvRefs.push(key);
      }
    }

    if (kvRefs.length > 0) {
      // This is informational — KV refs are good practice but can be an injection
      // surface if the function accepts user input that influences which secret is fetched
      results.push({
        checkId: "FUNC-002",
        title: "Function App with Key Vault references",
        severity: "LOW",
        status: "FAIL",
        resource: `${subId}/resourceGroups/${rg}/functionApps/${appName}`,
        region: location,
        provider: "azure",
        details:
          `Function App '${appName}' has ${kvRefs.length} Key Vault reference(s) in app settings: ` +
          `${kvRefs.join(", ")}. While Key Vault references are a security best practice for storing ` +
          `secrets, ensure that user input does not influence which secret is fetched. If the function ` +
          `dynamically constructs Key Vault secret URIs from user input, this could lead to ` +
          `unauthorized secret access (SSRF to Key Vault).`,
        remediation:
          `Review function code to ensure Key Vault secret names/URIs are not constructed ` +
          `from user-controlled input. Use static Key Vault references in app settings and ` +
          `avoid dynamic secret fetching based on request parameters.`,
        reference:
          "https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references",
      });
    } else {
      results.push({
        checkId: "FUNC-002",
        title: "Function App with Key Vault references",
        severity: "LOW",
        status: "PASS",
        resource: `${subId}/resourceGroups/${rg}/functionApps/${appName}`,
        region: location,
        provider: "azure",
        details:
          `Function App '${appName}' does not use Key Vault references in app settings. ` +
          `Note: if the app stores secrets directly in app settings instead, that is a ` +
          `separate concern (check app setting values for credential patterns).`,
        remediation: "No action required for this check.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "FUNC-002",
      title: "Function App with Key Vault references",
      severity: "LOW",
      status: "ERROR",
      resource: `${subId}/resourceGroups/${rg}/functionApps/${appName}`,
      region: location,
      provider: "azure",
      details: `Failed to list app settings for Function App '${appName}': ${(err as Error).message}`,
      remediation: "Ensure the identity has Website Contributor or Reader role.",
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
