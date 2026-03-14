import type { AzureClientFactory } from "./client.js";
import type { CheckResult } from "../types/index.js";

interface WebappArgs {
  resourceGroup?: string;
}

// Patterns that indicate credentials in connection strings
const CREDENTIAL_PATTERNS = [
  /Password\s*=\s*[^;]+/i,
  /Pwd\s*=\s*[^;]+/i,
  /SharedAccessKey\s*=\s*[^;]+/i,
  /AccountKey\s*=\s*[^;]+/i,
  /AccessKey\s*=\s*[^;]+/i,
  /SharedAccessSignature\s*=\s*[^;]+/i,
  /client_secret\s*=\s*[^;]+/i,
];

/**
 * WEBAPP-001: SCM basic auth enabled
 * WEBAPP-002: Connection strings with credentials
 * WEBAPP-003: Deployment packages in accessible storage
 */
export async function checkWebapp(
  azure: AzureClientFactory,
  args: WebappArgs = {},
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
          // Skip Function Apps (handled by functions.ts)
          const kind = (app.kind || "").toLowerCase();
          if (kind.includes("functionapp")) continue;

          const appName = app.name || "unknown";
          const location = app.location || "unknown";

          // WEBAPP-001: Check SCM basic auth
          await checkScmAuth(client, rg, appName, location, subId, results);

          // WEBAPP-002: Check connection strings for credentials
          await checkConnectionStrings(client, rg, appName, location, subId, results);

          // WEBAPP-003: Check deployment configuration
          await checkDeploymentConfig(client, rg, appName, location, subId, app, results);
        }
      } catch (rgErr) {
        const errMsg = (rgErr as Error).message || "";
        if (!errMsg.includes("not found") && !errMsg.includes("NoRegisteredProviderFound")) {
          results.push({
            checkId: "WEBAPP-001",
            title: "SCM basic auth enabled",
            severity: "MEDIUM",
            status: "ERROR",
            resource: `${subId}/resourceGroups/${rg}/webApps`,
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
      checkId: "WEBAPP-001",
      title: "SCM basic auth enabled",
      severity: "MEDIUM",
      status: "ERROR",
      resource: `${subId}/webApps`,
      region: "global",
      provider: "azure",
      details: `Failed to enumerate web apps: ${(err as Error).message}`,
      remediation: "Ensure the identity has Reader role on the subscription.",
    });
  }

  return results;
}

async function checkScmAuth(
  client: ReturnType<AzureClientFactory["appService"]>,
  rg: string,
  appName: string,
  location: string,
  subId: string,
  results: CheckResult[],
): Promise<void> {
  try {
    // Check if basic auth is enabled for SCM (Kudu) site
    // This is controlled by the basicPublishingCredentialsPolicies resource
    let scmBasicAuthEnabled = true; // Default is enabled

    try {
      const scmPolicy = await client.webApps.getScmAllowed(rg, appName);
      scmBasicAuthEnabled = scmPolicy.allow !== false;
    } catch {
      // If we can't check the policy, fall back to checking publishing profile
      try {
        const publishProfile = await client.webApps.beginListPublishingCredentialsAndWait(rg, appName);
        // If publishing credentials exist and have a username, basic auth is likely enabled
        scmBasicAuthEnabled = !!publishProfile.publishingUserName;
      } catch {
        // Cannot determine — report as unknown
      }
    }

    // Also check FTP basic auth
    let ftpBasicAuthEnabled = true;
    try {
      const ftpPolicy = await client.webApps.getFtpAllowed(rg, appName);
      ftpBasicAuthEnabled = ftpPolicy.allow !== false;
    } catch {
      // Default assumption
    }

    if (scmBasicAuthEnabled || ftpBasicAuthEnabled) {
      const authTypes: string[] = [];
      if (scmBasicAuthEnabled) authTypes.push("SCM/Kudu");
      if (ftpBasicAuthEnabled) authTypes.push("FTP");

      results.push({
        checkId: "WEBAPP-001",
        title: "SCM basic auth enabled",
        severity: "MEDIUM",
        status: "FAIL",
        resource: `${subId}/resourceGroups/${rg}/webApps/${appName}`,
        region: location,
        provider: "azure",
        details:
          `Web App '${appName}' has basic authentication enabled for ${authTypes.join(" and ")}. ` +
          `Basic auth credentials (publishing profile username/password) can be used to deploy ` +
          `code and access the Kudu console. These credentials are shared across all users with ` +
          `sufficient RBAC permissions and do not support MFA. They can be leaked through stored ` +
          `publish profiles or CI/CD configurations.`,
        remediation:
          `Disable basic auth for SCM and FTP:\n` +
          `az resource update --resource-group ${rg} --name scm --namespace Microsoft.Web ` +
          `--resource-type basicPublishingCredentialsPolicies --parent sites/${appName} ` +
          `--set properties.allow=false\n` +
          `az resource update --resource-group ${rg} --name ftp --namespace Microsoft.Web ` +
          `--resource-type basicPublishingCredentialsPolicies --parent sites/${appName} ` +
          `--set properties.allow=false\n\n` +
          `Use Azure AD-based deployment (e.g., az webapp deploy, GitHub Actions with OIDC).`,
        reference:
          "https://learn.microsoft.com/en-us/azure/app-service/configure-basic-auth-disable",
      });
    } else {
      results.push({
        checkId: "WEBAPP-001",
        title: "SCM basic auth enabled",
        severity: "MEDIUM",
        status: "PASS",
        resource: `${subId}/resourceGroups/${rg}/webApps/${appName}`,
        region: location,
        provider: "azure",
        details:
          `Web App '${appName}' has basic authentication disabled for both SCM and FTP. ` +
          `Deployment requires Azure AD-based authentication.`,
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "WEBAPP-001",
      title: "SCM basic auth enabled",
      severity: "MEDIUM",
      status: "ERROR",
      resource: `${subId}/resourceGroups/${rg}/webApps/${appName}`,
      region: location,
      provider: "azure",
      details: `Failed to check SCM auth settings for '${appName}': ${(err as Error).message}`,
      remediation: "Ensure the identity has Website Contributor or Reader role.",
    });
  }
}

async function checkConnectionStrings(
  client: ReturnType<AzureClientFactory["appService"]>,
  rg: string,
  appName: string,
  location: string,
  subId: string,
  results: CheckResult[],
): Promise<void> {
  try {
    const connStrings = await client.webApps.listConnectionStrings(rg, appName);
    const properties = connStrings.properties || {};
    const credentialConnStrings: string[] = [];

    for (const [name, connStr] of Object.entries(properties)) {
      const value = connStr.value || "";
      // Check if the connection string uses Key Vault reference (safe)
      if (value.includes("@Microsoft.KeyVault(")) continue;

      for (const pattern of CREDENTIAL_PATTERNS) {
        if (pattern.test(value)) {
          credentialConnStrings.push(
            `'${name}' (type: ${connStr.type || "unknown"}) — contains credential pattern`,
          );
          break;
        }
      }
    }

    if (credentialConnStrings.length > 0) {
      results.push({
        checkId: "WEBAPP-002",
        title: "Connection strings with embedded credentials",
        severity: "HIGH",
        status: "FAIL",
        resource: `${subId}/resourceGroups/${rg}/webApps/${appName}`,
        region: location,
        provider: "azure",
        details:
          `Web App '${appName}' has ${credentialConnStrings.length} connection string(s) ` +
          `containing embedded credentials:\n` +
          credentialConnStrings.map((c) => `  - ${c}`).join("\n") +
          `\n\nConnection string values with passwords, keys, or secrets should use Key Vault ` +
          `references instead of plaintext values. Plaintext credentials in app settings are ` +
          `visible to anyone with Contributor role and appear in deployment logs.`,
        remediation:
          `Move credentials to Key Vault and use Key Vault references:\n` +
          `1. Store secret in Key Vault:\n` +
          `   az keyvault secret set --vault-name <vault> --name <secret-name> --value "<connection-string>"\n` +
          `2. Grant the web app identity access to Key Vault:\n` +
          `   az webapp identity assign --resource-group ${rg} --name ${appName}\n` +
          `   az keyvault set-policy --name <vault> --object-id <identity-id> --secret-permissions get\n` +
          `3. Update connection string to use Key Vault reference:\n` +
          `   @Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/<secret-name>/)`,
        reference:
          "https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references",
      });
    } else {
      const totalStrings = Object.keys(properties).length;
      results.push({
        checkId: "WEBAPP-002",
        title: "Connection strings with embedded credentials",
        severity: "HIGH",
        status: "PASS",
        resource: `${subId}/resourceGroups/${rg}/webApps/${appName}`,
        region: location,
        provider: "azure",
        details:
          totalStrings > 0
            ? `Web App '${appName}' has ${totalStrings} connection string(s), none of which ` +
              `contain obvious credential patterns (or they use Key Vault references).`
            : `Web App '${appName}' has no connection strings configured.`,
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "WEBAPP-002",
      title: "Connection strings with embedded credentials",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/resourceGroups/${rg}/webApps/${appName}`,
      region: location,
      provider: "azure",
      details: `Failed to list connection strings for '${appName}': ${(err as Error).message}`,
      remediation: "Ensure the identity has Website Contributor or Reader role.",
    });
  }
}

async function checkDeploymentConfig(
  client: ReturnType<AzureClientFactory["appService"]>,
  rg: string,
  appName: string,
  location: string,
  subId: string,
  app: any,
  results: CheckResult[],
): Promise<void> {
  try {
    // Check if the app uses Run From Package pointing to a storage URL
    const appSettings = await client.webApps.listApplicationSettings(rg, appName);
    const properties = appSettings.properties || {};
    const runFromPackage = properties["WEBSITE_RUN_FROM_PACKAGE"] || "";
    const runFromZip = properties["WEBSITE_RUN_FROM_ZIP"] || "";

    const packageUrl = runFromPackage || runFromZip;
    let isAccessibleStorage = false;
    let storageDetails = "";

    if (packageUrl && packageUrl !== "1") {
      // Check if it's a blob URL with a SAS token
      if (packageUrl.includes("blob.core.windows.net")) {
        isAccessibleStorage = true;
        if (packageUrl.includes("sig=")) {
          storageDetails =
            `The deployment package URL includes a SAS token, which could be leaked through ` +
            `app settings exposure. If the SAS token is long-lived, the package can be ` +
            `downloaded by anyone with the URL.`;
        } else {
          storageDetails =
            `The deployment package URL points to Azure Blob Storage without a SAS token. ` +
            `The blob may be accessible if the container has public access enabled.`;
        }
      }
    }

    if (isAccessibleStorage) {
      results.push({
        checkId: "WEBAPP-003",
        title: "Deployment package in accessible storage",
        severity: "MEDIUM",
        status: "FAIL",
        resource: `${subId}/resourceGroups/${rg}/webApps/${appName}`,
        region: location,
        provider: "azure",
        details:
          `Web App '${appName}' uses Run From Package with an external storage URL. ` +
          `${storageDetails} The deployment package may contain application source code, ` +
          `configuration files, and potentially embedded credentials.`,
        remediation:
          `Use Run From Package with value "1" (deploy from internal storage) instead of external URLs:\n` +
          `az webapp config appsettings set --resource-group ${rg} --name ${appName} ` +
          `--settings WEBSITE_RUN_FROM_PACKAGE=1\n` +
          `az webapp deploy --resource-group ${rg} --name ${appName} --src-path <package.zip> --type zip\n\n` +
          `If external storage is required, use managed identity authentication instead of SAS tokens.`,
        reference:
          "https://learn.microsoft.com/en-us/azure/app-service/deploy-run-package",
      });
    } else {
      results.push({
        checkId: "WEBAPP-003",
        title: "Deployment package in accessible storage",
        severity: "MEDIUM",
        status: "PASS",
        resource: `${subId}/resourceGroups/${rg}/webApps/${appName}`,
        region: location,
        provider: "azure",
        details:
          packageUrl === "1"
            ? `Web App '${appName}' uses Run From Package with internal storage (value "1"). ` +
              `The deployment package is stored securely in the app's internal blob storage.`
            : `Web App '${appName}' does not use external storage URLs for deployment packages.`,
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "WEBAPP-003",
      title: "Deployment package in accessible storage",
      severity: "MEDIUM",
      status: "ERROR",
      resource: `${subId}/resourceGroups/${rg}/webApps/${appName}`,
      region: location,
      provider: "azure",
      details: `Failed to check deployment config for '${appName}': ${(err as Error).message}`,
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
