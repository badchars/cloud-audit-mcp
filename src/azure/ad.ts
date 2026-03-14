import type { AzureClientFactory } from "./client.js";
import type { CheckResult } from "../types/index.js";

interface AdArgs {
  resourceGroup?: string;
}

/**
 * AAD-001: Secrets in AD object descriptions
 * AAD-002: User consent settings for OAuth apps
 *
 * NOTE: These checks require Microsoft Graph API access, which is not available
 * through the Azure ARM SDK. The ARM SDK (@azure/arm-*) only covers Azure
 * Resource Manager operations. Azure AD / Entra ID operations require:
 *   - @microsoft/microsoft-graph-client
 *   - @azure/identity with appropriate Graph API scopes
 *
 * This module returns NOT_APPLICABLE status until Graph API integration is added.
 */
export async function checkAdConsent(
  azure: AzureClientFactory,
  args: AdArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const subId = azure.getSubscriptionId();

  // AAD-001: Secrets in Azure AD object descriptions
  // Requires Graph API: GET /applications, GET /servicePrincipals, GET /groups
  // Check description, notes fields for patterns like passwords, keys, tokens
  results.push({
    checkId: "AAD-001",
    title: "Secrets in Azure AD object descriptions",
    severity: "HIGH",
    status: "NOT_APPLICABLE",
    resource: `${subId}/azureAD/objects`,
    region: "global",
    provider: "azure",
    details:
      "This check requires Microsoft Graph API access to enumerate Azure AD applications, " +
      "service principals, and groups, then scan their description/notes fields for credential " +
      "patterns (passwords, API keys, connection strings). The ARM SDK does not provide access " +
      "to Azure AD objects. Install @microsoft/microsoft-graph-client and configure Graph API " +
      "permissions (Application.Read.All, Directory.Read.All) to enable this check.",
    remediation:
      "To enable this check, add Graph API integration:\n" +
      "1. Register an app in Azure AD with Application.Read.All and Directory.Read.All permissions\n" +
      "2. Install: bun add @microsoft/microsoft-graph-client @azure/identity\n" +
      "3. Query: GET /applications?$select=displayName,description,notes\n" +
      "4. Scan description/notes fields for credential patterns",
    reference:
      "https://learn.microsoft.com/en-us/graph/api/application-list",
  });

  // AAD-002: User consent settings for OAuth apps
  // Requires Graph API: GET /policies/authorizationPolicy
  // Check defaultUserRolePermissions.permissionGrantPoliciesAssigned
  results.push({
    checkId: "AAD-002",
    title: "User consent settings for OAuth apps",
    severity: "HIGH",
    status: "NOT_APPLICABLE",
    resource: `${subId}/azureAD/consentSettings`,
    region: "global",
    provider: "azure",
    details:
      "This check requires Microsoft Graph API access to read the authorization policy and " +
      "determine whether users can consent to OAuth applications on their own. Unrestricted " +
      "user consent allows any user to grant third-party apps access to organizational data, " +
      "which is a common phishing vector (illicit consent grant attack). The ARM SDK does not " +
      "provide access to Azure AD policies. Install @microsoft/microsoft-graph-client and " +
      "configure Graph API permissions (Policy.Read.All) to enable this check.",
    remediation:
      "To enable this check, add Graph API integration:\n" +
      "1. Configure Policy.Read.All permission\n" +
      "2. Query: GET /policies/authorizationPolicy\n" +
      "3. Check defaultUserRolePermissions.permissionGrantPoliciesAssigned\n" +
      "4. If set to 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy', users can consent to any app\n\n" +
      "To restrict user consent (recommended):\n" +
      "az ad sp update --id <enterprise-app-object-id> --set appRoleAssignmentRequired=true\n" +
      "Or configure admin consent workflow in Azure Portal > Enterprise Applications > User Settings",
    reference:
      "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent",
  });

  return results;
}
