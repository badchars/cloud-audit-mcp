import {
  DescribeRepositoriesCommand,
  DescribeImageScanFindingsCommand,
  ListImagesCommand,
} from "@aws-sdk/client-ecr";
import type { CheckResult } from "../types/index.js";
import type { AwsClientFactory } from "./client.js";

/**
 * ECR-001: Image scan findings
 * ECR-002: Image scanning enabled
 */
export async function checkEcrImages(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const ecr = aws.ecr(region);

  let repositories: {
    repositoryName?: string;
    repositoryArn?: string;
    repositoryUri?: string;
    imageScanningConfiguration?: { scanOnPush?: boolean };
  }[] = [];

  try {
    let nextToken: string | undefined;

    do {
      const resp = await ecr.send(
        new DescribeRepositoriesCommand({ nextToken }),
      );
      repositories.push(...(resp.repositories ?? []));
      nextToken = resp.nextToken;
    } while (nextToken);
  } catch (err) {
    results.push({
      checkId: "ECR-001",
      title: "ECR image scan findings",
      severity: "HIGH",
      status: "ERROR",
      resource: "ecr:repositories",
      region,
      provider: "aws",
      details: `Failed to describe repositories: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: ecr:DescribeRepositories",
    });
    return results;
  }

  if (repositories.length === 0) {
    results.push({
      checkId: "ECR-001",
      title: "ECR image scan findings",
      severity: "HIGH",
      status: "PASS",
      resource: "ecr:repositories",
      region,
      provider: "aws",
      details: "No ECR repositories found in this region.",
      remediation: "No action required.",
    });
    return results;
  }

  for (const repo of repositories) {
    const repoName = repo.repositoryName ?? "unknown";
    const repoArn = repo.repositoryArn ?? `arn:aws:ecr:${region}:*:repository/${repoName}`;

    // --- ECR-002: Check if image scanning is enabled ---
    const scanOnPush = repo.imageScanningConfiguration?.scanOnPush ?? false;
    if (!scanOnPush) {
      results.push({
        checkId: "ECR-002",
        title: "ECR scan-on-push disabled",
        severity: "MEDIUM",
        status: "FAIL",
        resource: repoArn,
        region,
        provider: "aws",
        details: `Repository "${repoName}" does not have scan-on-push enabled. New images will not be automatically scanned for vulnerabilities.`,
        remediation: `aws ecr put-image-scanning-configuration --repository-name ${repoName} --image-scanning-configuration scanOnPush=true`,
        reference: "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
      });
    } else {
      results.push({
        checkId: "ECR-002",
        title: "ECR scan-on-push check",
        severity: "MEDIUM",
        status: "PASS",
        resource: repoArn,
        region,
        provider: "aws",
        details: `Repository "${repoName}" has scan-on-push enabled.`,
        remediation: "No action required.",
      });
    }

    // --- ECR-001: Check for image scan findings on latest image ---
    try {
      // Get the latest image to check scan findings
      const imagesResp = await ecr.send(
        new ListImagesCommand({
          repositoryName: repoName,
          maxResults: 10,
          filter: { tagStatus: "TAGGED" },
        }),
      );

      const images = imagesResp.imageIds ?? [];
      if (images.length === 0) {
        results.push({
          checkId: "ECR-001",
          title: "ECR image scan findings",
          severity: "HIGH",
          status: "PASS",
          resource: repoArn,
          region,
          provider: "aws",
          details: `Repository "${repoName}" has no tagged images.`,
          remediation: "No action required.",
        });
        continue;
      }

      // Check scan findings for first tagged image
      const imageId = images[0];
      let scanChecked = false;

      try {
        const scanResp = await ecr.send(
          new DescribeImageScanFindingsCommand({
            repositoryName: repoName,
            imageId: {
              imageDigest: imageId.imageDigest,
              imageTag: imageId.imageTag,
            },
          }),
        );

        scanChecked = true;
        const findings = scanResp.imageScanFindings;
        const counts = findings?.findingSeverityCounts ?? {};
        const critical = counts.CRITICAL ?? 0;
        const high = counts.HIGH ?? 0;
        const medium = counts.MEDIUM ?? 0;
        const low = counts.LOW ?? 0;
        const total = critical + high + medium + low;

        if (critical > 0 || high > 0) {
          results.push({
            checkId: "ECR-001",
            title: "ECR image has critical/high vulnerabilities",
            severity: critical > 0 ? "CRITICAL" : "HIGH",
            status: "FAIL",
            resource: repoArn,
            region,
            provider: "aws",
            details: `Image "${repoName}:${imageId.imageTag ?? imageId.imageDigest?.slice(0, 16)}" has ${total} vulnerabilities: ${critical} CRITICAL, ${high} HIGH, ${medium} MEDIUM, ${low} LOW.`,
            remediation: `Review and remediate image vulnerabilities:\naws ecr describe-image-scan-findings --repository-name ${repoName} --image-id imageTag=${imageId.imageTag ?? imageId.imageDigest}\nRebuild the image with updated base image and dependencies.`,
            reference: "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
          });
        } else if (total > 0) {
          results.push({
            checkId: "ECR-001",
            title: "ECR image has vulnerabilities",
            severity: "MEDIUM",
            status: "FAIL",
            resource: repoArn,
            region,
            provider: "aws",
            details: `Image "${repoName}:${imageId.imageTag ?? imageId.imageDigest?.slice(0, 16)}" has ${total} vulnerabilities: ${medium} MEDIUM, ${low} LOW. No CRITICAL or HIGH findings.`,
            remediation: `Review findings:\naws ecr describe-image-scan-findings --repository-name ${repoName} --image-id imageTag=${imageId.imageTag ?? imageId.imageDigest}`,
            reference: "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
          });
        } else {
          results.push({
            checkId: "ECR-001",
            title: "ECR image scan findings",
            severity: "HIGH",
            status: "PASS",
            resource: repoArn,
            region,
            provider: "aws",
            details: `Image "${repoName}:${imageId.imageTag ?? imageId.imageDigest?.slice(0, 16)}" has no known vulnerabilities.`,
            remediation: "No action required.",
          });
        }
      } catch (err) {
        const code = (err as any).name ?? (err as any).Code;
        if (code === "ScanNotFoundException") {
          results.push({
            checkId: "ECR-001",
            title: "ECR image not scanned",
            severity: "MEDIUM",
            status: "FAIL",
            resource: repoArn,
            region,
            provider: "aws",
            details: `No scan results found for "${repoName}:${imageId.imageTag ?? imageId.imageDigest?.slice(0, 16)}". Image has never been scanned.`,
            remediation: `Start a manual scan:\naws ecr start-image-scan --repository-name ${repoName} --image-id imageTag=${imageId.imageTag ?? imageId.imageDigest}`,
            reference: "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
          });
        } else if (!scanChecked) {
          results.push({
            checkId: "ECR-001",
            title: "ECR image scan findings",
            severity: "HIGH",
            status: "ERROR",
            resource: repoArn,
            region,
            provider: "aws",
            details: `Failed to get scan findings for "${repoName}": ${(err as Error).message}`,
            remediation: "Verify IAM permissions: ecr:DescribeImageScanFindings",
          });
        }
      }
    } catch (err) {
      results.push({
        checkId: "ECR-001",
        title: "ECR image scan findings",
        severity: "HIGH",
        status: "ERROR",
        resource: repoArn,
        region,
        provider: "aws",
        details: `Failed to list images for "${repoName}": ${(err as Error).message}`,
        remediation: "Verify IAM permissions: ecr:ListImages",
      });
    }
  }

  return results;
}
