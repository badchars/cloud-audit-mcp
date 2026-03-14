import {
  ListPoliciesCommand,
  ListPolicyVersionsCommand,
  GetPolicyVersionCommand,
  ListRolesCommand,
  ListAttachedRolePoliciesCommand,
} from "@aws-sdk/client-iam";
import type { CheckResult } from "../types/index.js";
import type { AwsClientFactory } from "./client.js";

// Actions that enable privilege escalation via policy version manipulation
const POLICY_VERSION_ESCALATION_ACTIONS = [
  "iam:CreatePolicyVersion",
  "iam:SetDefaultPolicyVersion",
];

// Dangerous action combinations that can lead to privilege escalation
const DANGEROUS_COMBOS: { name: string; actions: string[] }[] = [
  {
    name: "PassRole + Lambda (code execution as role)",
    actions: ["iam:PassRole", "lambda:CreateFunction"],
  },
  {
    name: "PassRole + EC2 (instance with role)",
    actions: ["iam:PassRole", "ec2:RunInstances"],
  },
  {
    name: "AttachUserPolicy (attach admin to self)",
    actions: ["iam:AttachUserPolicy"],
  },
  {
    name: "PutUserPolicy (inline admin on self)",
    actions: ["iam:PutUserPolicy"],
  },
  {
    name: "AttachRolePolicy (attach admin to any role)",
    actions: ["iam:AttachRolePolicy"],
  },
  {
    name: "PutRolePolicy (inline admin on any role)",
    actions: ["iam:PutRolePolicy"],
  },
  {
    name: "PassRole + SageMaker (notebook with role)",
    actions: ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
  },
  {
    name: "UpdateAssumeRolePolicy (hijack any role)",
    actions: ["iam:UpdateAssumeRolePolicy"],
  },
];

function actionMatches(policyAction: string, targetAction: string): boolean {
  if (policyAction === "*") return true;
  const re = new RegExp("^" + policyAction.replace(/\*/g, ".*") + "$", "i");
  return re.test(targetAction);
}

function extractActions(document: any): string[] {
  const actions: string[] = [];
  for (const stmt of document?.Statement ?? []) {
    if (stmt.Effect !== "Allow") continue;
    const stmtActions = Array.isArray(stmt.Action) ? stmt.Action : stmt.Action ? [stmt.Action] : [];
    actions.push(...stmtActions);
  }
  return actions;
}

/**
 * IAM-001: Policy version escalation
 * IAM-002: Dangerous action combinations
 * IAM-003: Lambda execution roles with admin
 */
export async function checkIamPolicies(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const iam = aws.iam();

  // --- IAM-001 & IAM-002: Check customer-managed policies ---
  try {
    let marker: string | undefined;
    let allPolicies: { Arn?: string; PolicyName?: string; DefaultVersionId?: string }[] = [];

    do {
      const resp = await iam.send(
        new ListPoliciesCommand({ Scope: "Local", Marker: marker, MaxItems: 100 }),
      );
      allPolicies.push(...(resp.Policies ?? []));
      marker = resp.IsTruncated ? resp.Marker : undefined;
    } while (marker);

    for (const policy of allPolicies) {
      const policyArn = policy.Arn ?? "unknown";
      const policyName = policy.PolicyName ?? "unknown";

      // Get all versions to check for version manipulation risk
      try {
        const versionsResp = await iam.send(
          new ListPolicyVersionsCommand({ PolicyArn: policyArn }),
        );
        const versions = versionsResp.Versions ?? [];

        // If policy has multiple versions, flag the non-default ones as potential escalation vectors
        if (versions.length >= 4) {
          results.push({
            checkId: "IAM-001",
            title: "Policy approaching version limit",
            severity: "LOW",
            status: "FAIL",
            resource: policyArn,
            region: "global",
            provider: "aws",
            details: `Policy "${policyName}" has ${versions.length}/5 versions. An attacker with iam:CreatePolicyVersion could replace the default version to escalate privileges.`,
            remediation: `aws iam delete-policy-version --policy-arn ${policyArn} --version-id <old-version>`,
            reference: "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
          });
        }
      } catch {
        // Non-fatal
      }

      // Get the default policy version document
      try {
        const versionResp = await iam.send(
          new GetPolicyVersionCommand({
            PolicyArn: policyArn,
            VersionId: policy.DefaultVersionId ?? "v1",
          }),
        );

        const doc = JSON.parse(
          decodeURIComponent(versionResp.PolicyVersion?.Document ?? "{}"),
        );
        const allowedActions = extractActions(doc);

        // IAM-001: Check for policy version escalation actions
        for (const escalationAction of POLICY_VERSION_ESCALATION_ACTIONS) {
          if (allowedActions.some((a) => actionMatches(a, escalationAction))) {
            results.push({
              checkId: "IAM-001",
              title: "Policy version escalation risk",
              severity: "CRITICAL",
              status: "FAIL",
              resource: policyArn,
              region: "global",
              provider: "aws",
              details: `Policy "${policyName}" grants "${escalationAction}". An attacker can create a new policy version with admin permissions and set it as default.`,
              remediation: `Remove "${escalationAction}" from policy "${policyName}" or scope it with resource/condition constraints.\naws iam create-policy-version --policy-arn ${policyArn} --policy-document file://restricted-policy.json --set-as-default`,
              reference: "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
            });
          }
        }

        // IAM-002: Check for dangerous action combinations
        for (const combo of DANGEROUS_COMBOS) {
          const hasAll = combo.actions.every((target) =>
            allowedActions.some((a) => actionMatches(a, target)),
          );
          if (hasAll) {
            results.push({
              checkId: "IAM-002",
              title: "Dangerous IAM action combination",
              severity: "CRITICAL",
              status: "FAIL",
              resource: policyArn,
              region: "global",
              provider: "aws",
              details: `Policy "${policyName}" has dangerous combo: ${combo.name} (${combo.actions.join(" + ")}). This can lead to privilege escalation.`,
              remediation: `Restrict or separate these actions in policy "${policyName}". Apply least-privilege principle.\naws iam create-policy-version --policy-arn ${policyArn} --policy-document file://least-privilege.json --set-as-default`,
              reference: "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
            });
          }
        }

        // If nothing flagged for this policy, record PASS
        const hasFail = results.some(
          (r) =>
            r.resource === policyArn &&
            (r.checkId === "IAM-001" || r.checkId === "IAM-002") &&
            r.status === "FAIL",
        );
        if (!hasFail) {
          results.push({
            checkId: "IAM-002",
            title: "IAM policy privilege escalation check",
            severity: "CRITICAL",
            status: "PASS",
            resource: policyArn,
            region: "global",
            provider: "aws",
            details: `Policy "${policyName}" has no dangerous action combinations or version escalation risks.`,
            remediation: "No action required.",
          });
        }
      } catch (err) {
        results.push({
          checkId: "IAM-001",
          title: "Policy version escalation",
          severity: "CRITICAL",
          status: "ERROR",
          resource: policyArn,
          region: "global",
          provider: "aws",
          details: `Failed to get policy version: ${(err as Error).message}`,
          remediation: "Verify IAM permissions: iam:GetPolicyVersion",
        });
      }
    }

    if (allPolicies.length === 0) {
      results.push({
        checkId: "IAM-001",
        title: "Policy version escalation",
        severity: "CRITICAL",
        status: "PASS",
        resource: "iam:policies",
        region: "global",
        provider: "aws",
        details: "No customer-managed policies found.",
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "IAM-001",
      title: "Policy version escalation",
      severity: "CRITICAL",
      status: "ERROR",
      resource: "iam:policies",
      region: "global",
      provider: "aws",
      details: `Failed to list policies: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: iam:ListPolicies",
    });
  }

  // --- IAM-003: Lambda execution roles with admin ---
  try {
    let marker: string | undefined;
    let allRoles: { RoleName?: string; Arn?: string; AssumeRolePolicyDocument?: string }[] = [];

    do {
      const resp = await iam.send(new ListRolesCommand({ Marker: marker, MaxItems: 100 }));
      allRoles.push(...(resp.Roles ?? []));
      marker = resp.IsTruncated ? resp.Marker : undefined;
    } while (marker);

    for (const role of allRoles) {
      const roleName = role.RoleName ?? "unknown";
      const roleArn = role.Arn ?? "unknown";

      // Check if Lambda is in the trust policy
      let trustDoc: any;
      try {
        trustDoc = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument ?? "{}"));
      } catch {
        continue;
      }

      const isLambdaTrusted = (trustDoc.Statement ?? []).some((stmt: any) => {
        const principal = stmt.Principal;
        if (!principal) return false;
        const services = Array.isArray(principal.Service) ? principal.Service : [principal.Service];
        return services.some((s: string) => s?.includes("lambda.amazonaws.com"));
      });

      if (!isLambdaTrusted) continue;

      // Check attached policies for AdministratorAccess
      try {
        const attachedResp = await iam.send(
          new ListAttachedRolePoliciesCommand({ RoleName: roleName }),
        );
        const attachedPolicies = attachedResp.AttachedPolicies ?? [];

        const hasAdmin = attachedPolicies.some(
          (p) =>
            p.PolicyName === "AdministratorAccess" ||
            p.PolicyArn === "arn:aws:iam::aws:policy/AdministratorAccess" ||
            p.PolicyArn?.endsWith(":policy/AdministratorAccess"),
        );

        if (hasAdmin) {
          results.push({
            checkId: "IAM-003",
            title: "Lambda execution role with AdministratorAccess",
            severity: "CRITICAL",
            status: "FAIL",
            resource: roleArn,
            region: "global",
            provider: "aws",
            details: `Role "${roleName}" is trusted by Lambda and has AdministratorAccess attached. Any Lambda function using this role has full AWS access.`,
            remediation: `Detach AdministratorAccess and apply least-privilege policy:\naws iam detach-role-policy --role-name ${roleName} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`,
            reference: "https://docs.aws.amazon.com/lambda/latest/dg/lambda-permissions.html",
          });
        } else {
          results.push({
            checkId: "IAM-003",
            title: "Lambda execution role check",
            severity: "CRITICAL",
            status: "PASS",
            resource: roleArn,
            region: "global",
            provider: "aws",
            details: `Lambda execution role "${roleName}" does not have AdministratorAccess.`,
            remediation: "No action required.",
          });
        }
      } catch {
        // Non-fatal
      }
    }
  } catch (err) {
    results.push({
      checkId: "IAM-003",
      title: "Lambda execution role with admin",
      severity: "CRITICAL",
      status: "ERROR",
      resource: "iam:roles",
      region: "global",
      provider: "aws",
      details: `Failed to list roles: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: iam:ListRoles",
    });
  }

  return results;
}
