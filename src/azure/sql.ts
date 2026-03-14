import type { AzureClientFactory } from "./client.js";
import type { CheckResult } from "../types/index.js";

interface SqlArgs {
  resourceGroup?: string;
}

/**
 * SQL-001: SQL authentication enabled (should use Azure AD only)
 * SQL-002: Overly permissive firewall rules
 */
export async function checkSql(
  azure: AzureClientFactory,
  args: SqlArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const client = azure.sql();
  const subId = azure.getSubscriptionId();

  try {
    const resourceGroups = await getResourceGroups(azure, args.resourceGroup);

    for (const rg of resourceGroups) {
      try {
        const servers = client.servers.listByResourceGroup(rg);

        for await (const server of servers) {
          const serverName = server.name || "unknown";
          const location = server.location || "unknown";

          // SQL-001: Check if Azure AD-only authentication is enabled
          await checkSqlAuthMode(client, rg, serverName, location, subId, server, results);

          // SQL-002: Check firewall rules for overly permissive entries
          await checkSqlFirewall(client, rg, serverName, location, subId, results);
        }
      } catch (rgErr) {
        const errMsg = (rgErr as Error).message || "";
        if (!errMsg.includes("not found") && !errMsg.includes("NoRegisteredProviderFound")) {
          results.push({
            checkId: "SQL-001",
            title: "SQL authentication enabled",
            severity: "HIGH",
            status: "ERROR",
            resource: `${subId}/resourceGroups/${rg}/sqlServers`,
            region: "global",
            provider: "azure",
            details: `Failed to list SQL servers in resource group '${rg}': ${errMsg}`,
            remediation: "Ensure the identity has SQL Server Contributor or Reader role.",
          });
        }
      }
    }
  } catch (err) {
    results.push({
      checkId: "SQL-001",
      title: "SQL authentication enabled",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/sqlServers`,
      region: "global",
      provider: "azure",
      details: `Failed to enumerate SQL servers: ${(err as Error).message}`,
      remediation: "Ensure the identity has Reader role on the subscription.",
    });
  }

  return results;
}

async function checkSqlAuthMode(
  client: ReturnType<AzureClientFactory["sql"]>,
  rg: string,
  serverName: string,
  location: string,
  subId: string,
  server: any,
  results: CheckResult[],
): Promise<void> {
  try {
    // Check Azure AD administrators
    let hasAzureAdAdmin = false;
    let azureAdOnlyAuth = false;

    try {
      const admins = client.serverAzureADAdministrators.listByServer(rg, serverName);
      for await (const admin of admins) {
        hasAzureAdAdmin = true;
        // Check if Azure AD only authentication is enabled
        if (admin.azureADOnlyAuthentication === true) {
          azureAdOnlyAuth = true;
        }
      }
    } catch {
      // May not have permission to list AD admins
    }

    // Also check via the server properties
    // The server.administrators property may contain this info
    const adminProps = server.administrators;
    if (adminProps?.azureADOnlyAuthentication === true) {
      azureAdOnlyAuth = true;
    }

    if (!hasAzureAdAdmin) {
      results.push({
        checkId: "SQL-001",
        title: "SQL authentication enabled",
        severity: "HIGH",
        status: "FAIL",
        resource: `${subId}/resourceGroups/${rg}/sqlServers/${serverName}`,
        region: location,
        provider: "azure",
        details:
          `SQL Server '${serverName}' does not have an Azure AD administrator configured. ` +
          `Authentication relies solely on SQL authentication (username/password), which is ` +
          `weaker than Azure AD-based authentication. SQL passwords can be brute-forced and ` +
          `do not support MFA, conditional access, or centralized identity management.`,
        remediation:
          `Set an Azure AD administrator and enable Azure AD-only authentication:\n` +
          `az sql server ad-admin create --resource-group ${rg} --server ${serverName} ` +
          `--display-name <admin-name> --object-id <admin-object-id>\n` +
          `az sql server ad-only-auth enable --resource-group ${rg} --name ${serverName}`,
        reference:
          "https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure",
      });
    } else if (!azureAdOnlyAuth) {
      results.push({
        checkId: "SQL-001",
        title: "SQL authentication enabled",
        severity: "MEDIUM",
        status: "FAIL",
        resource: `${subId}/resourceGroups/${rg}/sqlServers/${serverName}`,
        region: location,
        provider: "azure",
        details:
          `SQL Server '${serverName}' has an Azure AD administrator configured but SQL ` +
          `authentication is still enabled (dual-mode). Both SQL logins and Azure AD logins ` +
          `are accepted. SQL authentication should be disabled for stronger security posture.`,
        remediation:
          `Enable Azure AD-only authentication:\n` +
          `az sql server ad-only-auth enable --resource-group ${rg} --name ${serverName}`,
        reference:
          "https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-azure-ad-only-authentication",
      });
    } else {
      results.push({
        checkId: "SQL-001",
        title: "SQL authentication enabled",
        severity: "HIGH",
        status: "PASS",
        resource: `${subId}/resourceGroups/${rg}/sqlServers/${serverName}`,
        region: location,
        provider: "azure",
        details:
          `SQL Server '${serverName}' has Azure AD-only authentication enabled. ` +
          `SQL authentication (username/password) is disabled.`,
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "SQL-001",
      title: "SQL authentication enabled",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/resourceGroups/${rg}/sqlServers/${serverName}`,
      region: location,
      provider: "azure",
      details: `Failed to check authentication mode for SQL Server '${serverName}': ${(err as Error).message}`,
      remediation: "Ensure the identity has SQL Server Contributor or Reader role.",
    });
  }
}

async function checkSqlFirewall(
  client: ReturnType<AzureClientFactory["sql"]>,
  rg: string,
  serverName: string,
  location: string,
  subId: string,
  results: CheckResult[],
): Promise<void> {
  try {
    const firewallRules = client.firewallRules.listByServer(rg, serverName);
    const dangerousRules: string[] = [];
    let allowAzureServices = false;

    for await (const rule of firewallRules) {
      const ruleName = rule.name || "unknown";
      const startIp = rule.startIpAddress || "";
      const endIp = rule.endIpAddress || "";

      // Check for "Allow Azure Services" rule (0.0.0.0 - 0.0.0.0)
      if (startIp === "0.0.0.0" && endIp === "0.0.0.0") {
        allowAzureServices = true;
        continue;
      }

      // Check for overly permissive rules
      if (startIp === "0.0.0.0" && endIp === "255.255.255.255") {
        dangerousRules.push(
          `Rule '${ruleName}': ${startIp} - ${endIp} (ALL IPs — entire internet)`,
        );
      } else if (isWideRange(startIp, endIp)) {
        dangerousRules.push(
          `Rule '${ruleName}': ${startIp} - ${endIp} (wide IP range)`,
        );
      }
    }

    if (dangerousRules.length > 0) {
      results.push({
        checkId: "SQL-002",
        title: "Overly permissive SQL Server firewall rules",
        severity: "CRITICAL",
        status: "FAIL",
        resource: `${subId}/resourceGroups/${rg}/sqlServers/${serverName}`,
        region: location,
        provider: "azure",
        details:
          `SQL Server '${serverName}' has overly permissive firewall rules:\n` +
          dangerousRules.map((r) => `  - ${r}`).join("\n") +
          (allowAzureServices
            ? `\n  - 'Allow Azure services' is also enabled (0.0.0.0 - 0.0.0.0)`
            : "") +
          `\nThis allows connections from a very wide range of IP addresses, significantly ` +
          `increasing the attack surface.`,
        remediation:
          `Remove overly permissive firewall rules and add specific IP ranges:\n` +
          `az sql server firewall-rule delete --resource-group ${rg} --server ${serverName} --name <rule-name>\n` +
          `az sql server firewall-rule create --resource-group ${rg} --server ${serverName} ` +
          `--name AllowSpecificIP --start-ip-address <your-ip> --end-ip-address <your-ip>\n\n` +
          `Consider using private endpoints instead of firewall rules:\n` +
          `az sql server update --resource-group ${rg} --name ${serverName} --enable-public-network-access false`,
        reference:
          "https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure",
      });
    } else if (allowAzureServices) {
      results.push({
        checkId: "SQL-002",
        title: "Overly permissive SQL Server firewall rules",
        severity: "MEDIUM",
        status: "FAIL",
        resource: `${subId}/resourceGroups/${rg}/sqlServers/${serverName}`,
        region: location,
        provider: "azure",
        details:
          `SQL Server '${serverName}' has 'Allow Azure services and resources to access this server' ` +
          `enabled (0.0.0.0 - 0.0.0.0 rule). This allows any Azure resource (including resources ` +
          `in other tenants and subscriptions) to connect to the SQL server. While no extremely ` +
          `wide custom rules were found, the Azure services rule broadens access beyond your own resources.`,
        remediation:
          `Disable 'Allow Azure services' and use specific VNet rules or private endpoints:\n` +
          `az sql server firewall-rule delete --resource-group ${rg} --server ${serverName} --name AllowAllWindowsAzureIps\n` +
          `az sql server vnet-rule create --resource-group ${rg} --server ${serverName} ` +
          `--name AllowVnet --vnet-name <vnet> --subnet <subnet>`,
        reference:
          "https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure#connections-from-inside-azure",
      });
    } else {
      results.push({
        checkId: "SQL-002",
        title: "Overly permissive SQL Server firewall rules",
        severity: "CRITICAL",
        status: "PASS",
        resource: `${subId}/resourceGroups/${rg}/sqlServers/${serverName}`,
        region: location,
        provider: "azure",
        details:
          `SQL Server '${serverName}' does not have overly permissive firewall rules. ` +
          `Access is restricted to specific IP addresses.`,
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "SQL-002",
      title: "Overly permissive SQL Server firewall rules",
      severity: "CRITICAL",
      status: "ERROR",
      resource: `${subId}/resourceGroups/${rg}/sqlServers/${serverName}`,
      region: location,
      provider: "azure",
      details: `Failed to list firewall rules for SQL Server '${serverName}': ${(err as Error).message}`,
      remediation: "Ensure the identity has SQL Server Contributor or Reader role.",
    });
  }
}

/**
 * Check if an IP range covers more than a /16 (65536 IPs)
 */
function isWideRange(startIp: string, endIp: string): boolean {
  try {
    const startNum = ipToNumber(startIp);
    const endNum = ipToNumber(endIp);
    // If range covers more than 65536 IPs (/16), it's considered wide
    return endNum - startNum > 65536;
  } catch {
    return false;
  }
}

function ipToNumber(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
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
