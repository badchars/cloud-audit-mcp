import {
  ListNotebookInstancesCommand,
  DescribeNotebookInstanceCommand,
} from "@aws-sdk/client-sagemaker";
import type { CheckResult } from "../types/index.js";
import type { AwsClientFactory } from "./client.js";

/**
 * SAGE-001: SageMaker notebook instance security check
 * - DirectInternetAccess enabled
 * - RootAccess enabled
 * - Not in VPC (subnet)
 * - Unencrypted volumes
 */
export async function checkSageMaker(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const sage = aws.sageMaker(region);

  let notebooks: {
    NotebookInstanceName?: string;
    NotebookInstanceArn?: string;
    NotebookInstanceStatus?: string;
  }[] = [];

  try {
    let nextToken: string | undefined;

    do {
      const resp = await sage.send(
        new ListNotebookInstancesCommand({ NextToken: nextToken, MaxResults: 100 }),
      );
      notebooks.push(...(resp.NotebookInstances ?? []));
      nextToken = resp.NextToken;
    } while (nextToken);
  } catch (err) {
    results.push({
      checkId: "SAGE-001",
      title: "SageMaker notebook security",
      severity: "HIGH",
      status: "ERROR",
      resource: "sagemaker:notebook-instances",
      region,
      provider: "aws",
      details: `Failed to list notebook instances: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: sagemaker:ListNotebookInstances",
    });
    return results;
  }

  if (notebooks.length === 0) {
    results.push({
      checkId: "SAGE-001",
      title: "SageMaker notebook security",
      severity: "HIGH",
      status: "PASS",
      resource: "sagemaker:notebook-instances",
      region,
      provider: "aws",
      details: "No SageMaker notebook instances found in this region.",
      remediation: "No action required.",
    });
    return results;
  }

  for (const nb of notebooks) {
    const nbName = nb.NotebookInstanceName ?? "unknown";
    const nbArn = nb.NotebookInstanceArn ?? `arn:aws:sagemaker:${region}:*:notebook-instance/${nbName}`;

    // Skip deleted instances
    if (nb.NotebookInstanceStatus === "Deleting" || nb.NotebookInstanceStatus === "Failed") {
      continue;
    }

    try {
      const detail = await sage.send(
        new DescribeNotebookInstanceCommand({ NotebookInstanceName: nbName }),
      );

      const findings: { issue: string; severity: "CRITICAL" | "HIGH" | "MEDIUM" }[] = [];

      // Check DirectInternetAccess
      if (detail.DirectInternetAccess === "Enabled") {
        findings.push({
          issue: "DirectInternetAccess is Enabled — notebook can access the internet directly, risk of data exfiltration",
          severity: "HIGH",
        });
      }

      // Check RootAccess
      if (detail.RootAccess === "Enabled") {
        findings.push({
          issue: "RootAccess is Enabled — users can install arbitrary packages and modify the instance",
          severity: "MEDIUM",
        });
      }

      // Check VPC / subnet
      if (!detail.SubnetId) {
        findings.push({
          issue: "Notebook is not deployed in a VPC subnet — no network isolation",
          severity: "HIGH",
        });
      }

      // Check KMS encryption
      if (!detail.KmsKeyId) {
        findings.push({
          issue: "No KMS key configured for volume encryption — using default encryption only",
          severity: "MEDIUM",
        });
      }

      // Check instance type for cost/over-provisioning
      const instanceType = detail.InstanceType ?? "";
      if (instanceType.includes("xlarge") || instanceType.includes("metal")) {
        findings.push({
          issue: `Large instance type "${instanceType}" — verify this is necessary to avoid unnecessary cost and attack surface`,
          severity: "MEDIUM",
        });
      }

      if (findings.length > 0) {
        // Use the highest severity found
        const maxSeverity = findings.reduce((max, f) => {
          const order = { CRITICAL: 3, HIGH: 2, MEDIUM: 1 };
          return order[f.severity] > order[max] ? f.severity : max;
        }, "MEDIUM" as "CRITICAL" | "HIGH" | "MEDIUM");

        results.push({
          checkId: "SAGE-001",
          title: "SageMaker notebook instance security issues",
          severity: maxSeverity,
          status: "FAIL",
          resource: nbArn,
          region,
          provider: "aws",
          details: `Notebook "${nbName}" (Status: ${nb.NotebookInstanceStatus}, Type: ${instanceType}) has ${findings.length} security issue(s):\n${findings.map((f) => `  - [${f.severity}] ${f.issue}`).join("\n")}`,
          remediation: `Harden the notebook instance:\naws sagemaker stop-notebook-instance --notebook-instance-name ${nbName}\naws sagemaker update-notebook-instance --notebook-instance-name ${nbName} --direct-internet-access Disabled --root-access Disabled${!detail.SubnetId ? " --subnet-id <subnet-id> --security-group-ids <sg-id>" : ""}${!detail.KmsKeyId ? " --kms-key-id <key-id>" : ""}\naws sagemaker start-notebook-instance --notebook-instance-name ${nbName}`,
          reference: "https://docs.aws.amazon.com/sagemaker/latest/dg/notebook-interface-endpoint.html",
        });
      } else {
        results.push({
          checkId: "SAGE-001",
          title: "SageMaker notebook security",
          severity: "HIGH",
          status: "PASS",
          resource: nbArn,
          region,
          provider: "aws",
          details: `Notebook "${nbName}" has DirectInternetAccess disabled, RootAccess disabled, is in a VPC, and has KMS encryption.`,
          remediation: "No action required.",
        });
      }
    } catch (err) {
      results.push({
        checkId: "SAGE-001",
        title: "SageMaker notebook security",
        severity: "HIGH",
        status: "ERROR",
        resource: nbArn,
        region,
        provider: "aws",
        details: `Failed to describe notebook "${nbName}": ${(err as Error).message}`,
        remediation: "Verify IAM permissions: sagemaker:DescribeNotebookInstance",
      });
    }
  }

  return results;
}
