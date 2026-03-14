import type { AzureClientFactory } from "./client.js";
import type { CheckResult } from "../types/index.js";

interface AutomationArgs {
  resourceGroup?: string;
}

// Patterns that indicate hardcoded credentials in runbook content
const CREDENTIAL_PATTERNS = [
  /password\s*[:=]\s*["'][^"']+["']/i,
  /secret\s*[:=]\s*["'][^"']+["']/i,
  /apikey\s*[:=]\s*["'][^"']+["']/i,
  /api_key\s*[:=]\s*["'][^"']+["']/i,
  /connectionstring\s*[:=]\s*["'][^"']+["']/i,
  /ConvertTo-SecureString\s+["'][^"']+["']\s+-AsPlainText/i,
  /\$cred\s*=\s*New-Object.*PSCredential.*["'][^"']+["']/i,
  /access_key\s*[:=]\s*["'][^"']+["']/i,
  /client_secret\s*[:=]\s*["'][^"']+["']/i,
  /SAS\s*[:=]\s*["']sv=[^"']+["']/i,
];

/**
 * AUTO-001: Hardcoded credentials in runbooks
 * AUTO-002: DSC configuration plaintext passwords
 * AUTO-003: Unencrypted automation variables
 */
export async function checkAutomation(
  azure: AzureClientFactory,
  args: AutomationArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const client = azure.automation();
  const subId = azure.getSubscriptionId();

  try {
    // List all resource groups to iterate automation accounts
    const resourceGroups = await getResourceGroups(azure, args.resourceGroup);

    for (const rg of resourceGroups) {
      try {
        const accountsResult = await client.automationAccount.listByResourceGroup(rg);

        for (const account of accountsResult) {
          const accountName = account.name || "unknown";
          const location = account.location || "unknown";

          // AUTO-001: Check runbooks for hardcoded credentials
          await checkRunbookCredentials(
            client,
            rg,
            accountName,
            location,
            subId,
            results,
          );

          // AUTO-002: Check DSC configurations for plaintext passwords
          await checkDscConfigurations(
            client,
            rg,
            accountName,
            location,
            subId,
            results,
          );

          // AUTO-003: Check for unencrypted variables
          await checkUnencryptedVariables(
            client,
            rg,
            accountName,
            location,
            subId,
            results,
          );
        }
      } catch (rgErr) {
        // Resource group may not have automation accounts — not an error
        const errMsg = (rgErr as Error).message || "";
        if (!errMsg.includes("not found") && !errMsg.includes("NoRegisteredProviderFound")) {
          results.push({
            checkId: "AUTO-001",
            title: "Hardcoded credentials in runbooks",
            severity: "CRITICAL",
            status: "ERROR",
            resource: `${subId}/resourceGroups/${rg}/automationAccounts`,
            region: "global",
            provider: "azure",
            details: `Failed to list automation accounts in resource group '${rg}': ${errMsg}`,
            remediation: "Ensure the identity has Automation Operator or Reader role.",
          });
        }
      }
    }
  } catch (err) {
    results.push({
      checkId: "AUTO-001",
      title: "Hardcoded credentials in runbooks",
      severity: "CRITICAL",
      status: "ERROR",
      resource: `${subId}/automationAccounts`,
      region: "global",
      provider: "azure",
      details: `Failed to enumerate automation accounts: ${(err as Error).message}`,
      remediation: "Ensure the identity has Reader role on the subscription.",
    });
  }

  return results;
}

async function checkRunbookCredentials(
  client: ReturnType<AzureClientFactory["automation"]>,
  rg: string,
  accountName: string,
  location: string,
  subId: string,
  results: CheckResult[],
): Promise<void> {
  try {
    const runbooksResult = await client.runbook.listByAutomationAccount(rg, accountName);
    let hasRunbooks = false;

    for (const runbook of runbooksResult) {
      hasRunbooks = true;
      const runbookName = runbook.name || "unknown";
      let hasCreds = false;

      // Try to get runbook content to scan for credentials
      try {
        const content = await client.runbook.getContent(
          rg,
          accountName,
          runbookName,
        );
        // content is returned as a readable stream or string
        const contentStr = typeof content === "string"
          ? content
          : content?.toString() || "";

        if (contentStr) {
          for (const pattern of CREDENTIAL_PATTERNS) {
            if (pattern.test(contentStr)) {
              hasCreds = true;
              break;
            }
          }
        }
      } catch {
        // Content may not be accessible; skip content check
      }

      if (hasCreds) {
        results.push({
          checkId: "AUTO-001",
          title: "Hardcoded credentials in runbooks",
          severity: "CRITICAL",
          status: "FAIL",
          resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}/runbooks/${runbookName}`,
          region: location,
          provider: "azure",
          details: `Runbook '${runbookName}' in automation account '${accountName}' contains patterns that indicate hardcoded credentials (passwords, API keys, connection strings, or plaintext ConvertTo-SecureString calls).`,
          remediation: `Move credentials to Azure Key Vault or Automation Credentials. Use Get-AutomationPSCredential or Get-AzKeyVaultSecret in runbooks instead of hardcoded values.`,
          reference:
            "https://learn.microsoft.com/en-us/azure/automation/shared-resources/credentials",
        });
      } else {
        results.push({
          checkId: "AUTO-001",
          title: "Hardcoded credentials in runbooks",
          severity: "CRITICAL",
          status: "PASS",
          resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}/runbooks/${runbookName}`,
          region: location,
          provider: "azure",
          details: `Runbook '${runbookName}' does not contain obvious hardcoded credential patterns.`,
          remediation: "No action required.",
        });
      }
    }

    if (!hasRunbooks) {
      results.push({
        checkId: "AUTO-001",
        title: "Hardcoded credentials in runbooks",
        severity: "CRITICAL",
        status: "PASS",
        resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}`,
        region: location,
        provider: "azure",
        details: `Automation account '${accountName}' has no runbooks.`,
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "AUTO-001",
      title: "Hardcoded credentials in runbooks",
      severity: "CRITICAL",
      status: "ERROR",
      resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}/runbooks`,
      region: location,
      provider: "azure",
      details: `Failed to list runbooks: ${(err as Error).message}`,
      remediation: "Ensure the identity has Automation Runbook Operator role.",
    });
  }
}

async function checkDscConfigurations(
  client: ReturnType<AzureClientFactory["automation"]>,
  rg: string,
  accountName: string,
  location: string,
  subId: string,
  results: CheckResult[],
): Promise<void> {
  try {
    const configsResult = await client.dscConfiguration.listByAutomationAccount(rg, accountName);
    let hasConfigs = false;

    for (const config of configsResult) {
      hasConfigs = true;
      const configName = config.name || "unknown";
      let hasPlaintext = false;

      // Try to get DSC configuration content
      try {
        const content = await client.dscConfiguration.getContent(
          rg,
          accountName,
          configName,
        );
        const contentStr = typeof content === "string"
          ? content
          : content?.toString() || "";

        if (contentStr) {
          // Check for plaintext passwords in DSC configurations
          const dscPasswordPatterns = [
            /PsDscAllowPlainTextPassword\s*=\s*\$true/i,
            /Password\s*=\s*["'][^"']+["']/i,
            /Credential\s*=\s*New-Object.*["'][^"']+["']/i,
          ];
          for (const pattern of dscPasswordPatterns) {
            if (pattern.test(contentStr)) {
              hasPlaintext = true;
              break;
            }
          }
        }
      } catch {
        // Content may not be accessible
      }

      if (hasPlaintext) {
        results.push({
          checkId: "AUTO-002",
          title: "DSC configuration contains plaintext passwords",
          severity: "HIGH",
          status: "FAIL",
          resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}/dscConfigurations/${configName}`,
          region: location,
          provider: "azure",
          details: `DSC configuration '${configName}' contains plaintext passwords or has PsDscAllowPlainTextPassword enabled. This exposes credentials in the MOF file and during node configuration.`,
          remediation: `Use certificate-based encryption for DSC credentials. Remove PsDscAllowPlainTextPassword and use certificates to encrypt credentials in MOF files.`,
          reference:
            "https://learn.microsoft.com/en-us/powershell/dsc/pull-server/secureMOF",
        });
      } else {
        results.push({
          checkId: "AUTO-002",
          title: "DSC configuration contains plaintext passwords",
          severity: "HIGH",
          status: "PASS",
          resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}/dscConfigurations/${configName}`,
          region: location,
          provider: "azure",
          details: `DSC configuration '${configName}' does not contain obvious plaintext password patterns.`,
          remediation: "No action required.",
        });
      }
    }

    if (!hasConfigs) {
      results.push({
        checkId: "AUTO-002",
        title: "DSC configuration contains plaintext passwords",
        severity: "HIGH",
        status: "PASS",
        resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}`,
        region: location,
        provider: "azure",
        details: `Automation account '${accountName}' has no DSC configurations.`,
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "AUTO-002",
      title: "DSC configuration contains plaintext passwords",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}/dscConfigurations`,
      region: location,
      provider: "azure",
      details: `Failed to list DSC configurations: ${(err as Error).message}`,
      remediation: "Ensure the identity has appropriate permissions on the automation account.",
    });
  }
}

async function checkUnencryptedVariables(
  client: ReturnType<AzureClientFactory["automation"]>,
  rg: string,
  accountName: string,
  location: string,
  subId: string,
  results: CheckResult[],
): Promise<void> {
  try {
    const variablesResult = await client.variable.listByAutomationAccount(rg, accountName);
    let hasVariables = false;

    for (const variable of variablesResult) {
      hasVariables = true;
      const variableName = variable.name || "unknown";

      if (variable.isEncrypted === false) {
        results.push({
          checkId: "AUTO-003",
          title: "Unencrypted automation variable",
          severity: "MEDIUM",
          status: "FAIL",
          resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}/variables/${variableName}`,
          region: location,
          provider: "azure",
          details: `Variable '${variableName}' in automation account '${accountName}' is not encrypted. If this variable stores sensitive data, it is accessible in plaintext via the API and runbook execution context.`,
          remediation: `Delete the unencrypted variable and recreate it as encrypted:\naz automation variable delete --automation-account-name ${accountName} --resource-group ${rg} --name ${variableName}\naz automation variable create --automation-account-name ${accountName} --resource-group ${rg} --name ${variableName} --value "<value>" --encrypted true`,
          reference:
            "https://learn.microsoft.com/en-us/azure/automation/shared-resources/variables",
        });
      } else {
        results.push({
          checkId: "AUTO-003",
          title: "Unencrypted automation variable",
          severity: "MEDIUM",
          status: "PASS",
          resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}/variables/${variableName}`,
          region: location,
          provider: "azure",
          details: `Variable '${variableName}' in automation account '${accountName}' is encrypted.`,
          remediation: "No action required.",
        });
      }
    }

    if (!hasVariables) {
      results.push({
        checkId: "AUTO-003",
        title: "Unencrypted automation variable",
        severity: "MEDIUM",
        status: "PASS",
        resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}`,
        region: location,
        provider: "azure",
        details: `Automation account '${accountName}' has no variables.`,
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "AUTO-003",
      title: "Unencrypted automation variable",
      severity: "MEDIUM",
      status: "ERROR",
      resource: `${subId}/resourceGroups/${rg}/automationAccounts/${accountName}/variables`,
      region: location,
      provider: "azure",
      details: `Failed to list variables: ${(err as Error).message}`,
      remediation: "Ensure the identity has appropriate permissions on the automation account.",
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
