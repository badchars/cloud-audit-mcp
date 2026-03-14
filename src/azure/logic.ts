import type { AzureClientFactory } from "./client.js";
import type { CheckResult } from "../types/index.js";

interface LogicArgs {
  resourceGroup?: string;
}

/**
 * LOGIC-001: SSRF via managed identity in Logic Apps
 *
 * Logic Apps with HTTP triggers AND managed identity enabled present an SSRF risk.
 * An attacker who can trigger the Logic App (e.g., via webhook URL) may be able
 * to abuse the managed identity to access Azure resources, call ARM APIs, or
 * reach internal endpoints through the Logic App's HTTP actions.
 */
export async function checkLogicApps(
  azure: AzureClientFactory,
  args: LogicArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const client = azure.logic();
  const subId = azure.getSubscriptionId();

  try {
    const resourceGroups = await getResourceGroups(azure, args.resourceGroup);

    for (const rg of resourceGroups) {
      try {
        const workflows = client.workflows.listByResourceGroup(rg);

        for await (const workflow of workflows) {
          const workflowName = workflow.name || "unknown";
          const location = workflow.location || "unknown";
          const state = workflow.state || "Unknown";

          // Skip disabled workflows
          if (state === "Disabled") {
            results.push({
              checkId: "LOGIC-001",
              title: "SSRF via managed identity in Logic App",
              severity: "HIGH",
              status: "PASS",
              resource: `${subId}/resourceGroups/${rg}/workflows/${workflowName}`,
              region: location,
              provider: "azure",
              details: `Logic App '${workflowName}' is disabled.`,
              remediation: "No action required.",
            });
            continue;
          }

          const hasManagedIdentity =
            workflow.identity?.type === "SystemAssigned" ||
            workflow.identity?.type === "SystemAssigned, UserAssigned" ||
            workflow.identity?.type === "UserAssigned";

          // Check if the workflow has HTTP trigger
          let hasHttpTrigger = false;
          const definition = workflow.definition as Record<string, any> | undefined;

          if (definition?.triggers) {
            for (const [, trigger] of Object.entries(definition.triggers)) {
              const triggerObj = trigger as Record<string, any>;
              const triggerType = (triggerObj.type || "").toLowerCase();
              const triggerKind = (triggerObj.kind || "").toLowerCase();

              if (
                triggerType === "request" ||
                triggerType === "httpwebhook" ||
                triggerType === "http" ||
                triggerKind === "http"
              ) {
                hasHttpTrigger = true;
                break;
              }
            }
          }

          // Check for HTTP actions in the workflow that could be used for SSRF
          let hasHttpAction = false;
          if (definition?.actions) {
            for (const [, action] of Object.entries(definition.actions)) {
              const actionObj = action as Record<string, any>;
              const actionType = (actionObj.type || "").toLowerCase();
              if (actionType === "http" || actionType === "apiconnection") {
                hasHttpAction = true;
                break;
              }
            }
          }

          if (hasManagedIdentity && hasHttpTrigger) {
            results.push({
              checkId: "LOGIC-001",
              title: "SSRF via managed identity in Logic App",
              severity: "HIGH",
              status: "FAIL",
              resource: `${subId}/resourceGroups/${rg}/workflows/${workflowName}`,
              region: location,
              provider: "azure",
              details:
                `Logic App '${workflowName}' has an HTTP-based trigger and managed identity ` +
                `(${workflow.identity?.type}) enabled. ` +
                (hasHttpAction
                  ? "The workflow also contains HTTP actions that could be abused for SSRF. "
                  : "") +
                `An attacker who discovers the trigger URL can invoke the Logic App, which ` +
                `can then use the managed identity to authenticate to Azure services. This ` +
                `is a server-side request forgery (SSRF) vector that may allow access to ` +
                `ARM APIs, Key Vault secrets, or internal network resources.`,
              remediation:
                `1. Restrict the trigger to specific IPs:\n` +
                `   az logic workflow update --resource-group ${rg} --name ${workflowName} ` +
                `--access-control '{"triggers":{"allowedCallerIpAddresses":[{"addressRange":"<your-ip>/32"}]}}'\n` +
                `2. Use SAS key authentication on the trigger URL\n` +
                `3. Apply least-privilege roles to the managed identity\n` +
                `4. Use Azure API Management as a gateway in front of the Logic App`,
              reference:
                "https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app",
            });
          } else if (hasManagedIdentity && !hasHttpTrigger) {
            results.push({
              checkId: "LOGIC-001",
              title: "SSRF via managed identity in Logic App",
              severity: "LOW",
              status: "PASS",
              resource: `${subId}/resourceGroups/${rg}/workflows/${workflowName}`,
              region: location,
              provider: "azure",
              details:
                `Logic App '${workflowName}' has managed identity but no HTTP-based trigger. ` +
                `SSRF risk is lower since the workflow cannot be triggered externally via HTTP.`,
              remediation: "No action required. Continue to follow least-privilege for the managed identity.",
            });
          } else {
            results.push({
              checkId: "LOGIC-001",
              title: "SSRF via managed identity in Logic App",
              severity: "HIGH",
              status: "PASS",
              resource: `${subId}/resourceGroups/${rg}/workflows/${workflowName}`,
              region: location,
              provider: "azure",
              details:
                `Logic App '${workflowName}' does not have managed identity enabled` +
                (hasHttpTrigger ? " (has HTTP trigger but no identity to abuse)." : "."),
              remediation: "No action required.",
            });
          }
        }
      } catch (rgErr) {
        const errMsg = (rgErr as Error).message || "";
        if (!errMsg.includes("not found") && !errMsg.includes("NoRegisteredProviderFound")) {
          results.push({
            checkId: "LOGIC-001",
            title: "SSRF via managed identity in Logic App",
            severity: "HIGH",
            status: "ERROR",
            resource: `${subId}/resourceGroups/${rg}/workflows`,
            region: "global",
            provider: "azure",
            details: `Failed to list Logic Apps in resource group '${rg}': ${errMsg}`,
            remediation: "Ensure the identity has Logic App Operator or Reader role.",
          });
        }
      }
    }
  } catch (err) {
    results.push({
      checkId: "LOGIC-001",
      title: "SSRF via managed identity in Logic App",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/workflows`,
      region: "global",
      provider: "azure",
      details: `Failed to enumerate Logic Apps: ${(err as Error).message}`,
      remediation: "Ensure the identity has Reader role on the subscription.",
    });
  }

  return results;
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
