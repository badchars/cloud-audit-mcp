import {
  ListSecretsCommand,
  GetResourcePolicyCommand,
} from "@aws-sdk/client-secrets-manager";
import type { CheckResult } from "../types/index.js";
import type { AwsClientFactory } from "./client.js";

/**
 * SM-001: Over-permissive secret access (resource policy with Principal: "*")
 */
export async function checkSecretsManager(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const sm = aws.secretsManager(region);

  let secrets: { ARN?: string; Name?: string }[] = [];

  try {
    let nextToken: string | undefined;

    do {
      const resp = await sm.send(
        new ListSecretsCommand({ NextToken: nextToken, MaxResults: 100 }),
      );
      secrets.push(...(resp.SecretList ?? []));
      nextToken = resp.NextToken;
    } while (nextToken);
  } catch (err) {
    results.push({
      checkId: "SM-001",
      title: "Secrets Manager access policy",
      severity: "CRITICAL",
      status: "ERROR",
      resource: "secretsmanager:secrets",
      region,
      provider: "aws",
      details: `Failed to list secrets: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: secretsmanager:ListSecrets",
    });
    return results;
  }

  if (secrets.length === 0) {
    results.push({
      checkId: "SM-001",
      title: "Secrets Manager access policy",
      severity: "CRITICAL",
      status: "PASS",
      resource: "secretsmanager:secrets",
      region,
      provider: "aws",
      details: "No secrets found in this region.",
      remediation: "No action required.",
    });
    return results;
  }

  for (const secret of secrets) {
    const secretArn = secret.ARN ?? "unknown";
    const secretName = secret.Name ?? "unknown";

    try {
      const policyResp = await sm.send(
        new GetResourcePolicyCommand({ SecretId: secretArn }),
      );

      if (!policyResp.ResourcePolicy) {
        // No resource policy means access is controlled solely by IAM
        results.push({
          checkId: "SM-001",
          title: "Secrets Manager access policy",
          severity: "CRITICAL",
          status: "PASS",
          resource: secretArn,
          region,
          provider: "aws",
          details: `Secret "${secretName}" has no resource policy. Access is controlled by IAM policies only.`,
          remediation: "No action required.",
        });
        continue;
      }

      const policy = JSON.parse(policyResp.ResourcePolicy);
      const wildcardStatements: string[] = [];

      for (const stmt of policy.Statement ?? []) {
        if (stmt.Effect !== "Allow") continue;

        const principal = stmt.Principal;
        const isWildcard =
          principal === "*" ||
          principal?.AWS === "*" ||
          (Array.isArray(principal?.AWS) && principal.AWS.includes("*"));

        if (isWildcard) {
          // Check if there's a Condition that restricts it
          const hasCondition = stmt.Condition && Object.keys(stmt.Condition).length > 0;
          const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];

          if (hasCondition) {
            wildcardStatements.push(
              `Statement "${stmt.Sid ?? "unnamed"}" allows Principal:"*" but has Condition: ${JSON.stringify(stmt.Condition)} — actions: ${actions.join(", ")}`,
            );
          } else {
            wildcardStatements.push(
              `Statement "${stmt.Sid ?? "unnamed"}" allows Principal:"*" without Condition — actions: ${actions.join(", ")}`,
            );
          }
        }
      }

      if (wildcardStatements.length > 0) {
        // Determine severity: wildcard without condition is CRITICAL, with condition is HIGH
        const hasUnconditional = wildcardStatements.some((s) => s.includes("without Condition"));
        const severity = hasUnconditional ? "CRITICAL" : "HIGH";

        results.push({
          checkId: "SM-001",
          title: "Over-permissive secret resource policy",
          severity,
          status: "FAIL",
          resource: secretArn,
          region,
          provider: "aws",
          details: `Secret "${secretName}" has ${wildcardStatements.length} wildcard principal statement(s):\n${wildcardStatements.map((s) => `  - ${s}`).join("\n")}`,
          remediation: `Restrict the resource policy to specific principals:\naws secretsmanager put-resource-policy --secret-id ${secretName} --resource-policy file://restricted-policy.json\n\nOr remove the resource policy entirely:\naws secretsmanager delete-resource-policy --secret-id ${secretName}`,
          reference: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html",
        });
      } else {
        results.push({
          checkId: "SM-001",
          title: "Secrets Manager access policy",
          severity: "CRITICAL",
          status: "PASS",
          resource: secretArn,
          region,
          provider: "aws",
          details: `Secret "${secretName}" resource policy does not have wildcard principals.`,
          remediation: "No action required.",
        });
      }
    } catch (err) {
      const code = (err as any).name ?? (err as any).Code;
      if (code === "ResourceNotFoundException") {
        // Secret was deleted between list and get
        continue;
      }
      results.push({
        checkId: "SM-001",
        title: "Secrets Manager access policy",
        severity: "CRITICAL",
        status: "ERROR",
        resource: secretArn,
        region,
        provider: "aws",
        details: `Failed to get resource policy for "${secretName}": ${(err as Error).message}`,
        remediation: "Verify IAM permissions: secretsmanager:GetResourcePolicy",
      });
    }
  }

  return results;
}
