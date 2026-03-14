import {
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketPolicyCommand,
  GetBucketAclCommand,
  ListObjectsV2Command,
} from "@aws-sdk/client-s3";
import type { CheckResult } from "../types/index.js";
import type { AwsClientFactory } from "./client.js";

const ACCOUNT_ID_RE = /\b\d{12}\b/;

const SENSITIVE_PATTERNS = [
  /\.pem$/i,
  /\.key$/i,
  /id_rsa/i,
  /\.sql$/i,
  /\.env$/i,
  /credentials/i,
  /backup/i,
  /dump/i,
  /\.pfx$/i,
  /\.p12$/i,
  /\.jks$/i,
  /secret/i,
  /\.bak$/i,
  /password/i,
];

/**
 * S3-001: Public bucket access
 * S3-003: Bucket name leaks account ID
 */
export async function checkS3Public(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const s3 = aws.s3(region);

  let buckets: { Name?: string }[] = [];
  try {
    const resp = await s3.send(new ListBucketsCommand({}));
    buckets = resp.Buckets ?? [];
  } catch (err) {
    results.push({
      checkId: "S3-001",
      title: "Public bucket access",
      severity: "CRITICAL",
      status: "ERROR",
      resource: "s3:*",
      region,
      provider: "aws",
      details: `Failed to list buckets: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: s3:ListAllMyBuckets",
    });
    return results;
  }

  for (const bucket of buckets) {
    const name = bucket.Name ?? "unknown";
    const arn = `arn:aws:s3:::${name}`;

    // --- S3-003: Bucket name leaks account ID ---
    if (ACCOUNT_ID_RE.test(name)) {
      results.push({
        checkId: "S3-003",
        title: "Bucket name leaks account ID",
        severity: "LOW",
        status: "FAIL",
        resource: arn,
        region,
        provider: "aws",
        details: `Bucket name "${name}" contains a 12-digit pattern that may expose the AWS account ID.`,
        remediation: "Rename the bucket to remove the account ID from its name. Account IDs can be used in privilege escalation attacks.",
        reference: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html",
      });
    }

    // --- S3-001a: Block Public Access ---
    let blockPublicAccess = false;
    try {
      const bpa = await s3.send(new GetPublicAccessBlockCommand({ Bucket: name }));
      const cfg = bpa.PublicAccessBlockConfiguration;
      if (
        cfg?.BlockPublicAcls &&
        cfg?.IgnorePublicAcls &&
        cfg?.BlockPublicPolicy &&
        cfg?.RestrictPublicBuckets
      ) {
        blockPublicAccess = true;
      }
    } catch (err) {
      const code = (err as any).name ?? (err as any).Code;
      if (code !== "NoSuchPublicAccessBlockConfiguration") {
        results.push({
          checkId: "S3-001",
          title: "Public bucket access - Block Public Access",
          severity: "CRITICAL",
          status: "ERROR",
          resource: arn,
          region,
          provider: "aws",
          details: `Failed to get public access block: ${(err as Error).message}`,
          remediation: "Verify IAM permissions: s3:GetBucketPublicAccessBlock",
        });
        continue;
      }
      // No block config means public access is not blocked
    }

    if (!blockPublicAccess) {
      results.push({
        checkId: "S3-001",
        title: "Public bucket access - Block Public Access disabled",
        severity: "CRITICAL",
        status: "FAIL",
        resource: arn,
        region,
        provider: "aws",
        details: "S3 Block Public Access is not fully enabled. The bucket may be publicly accessible.",
        remediation: `aws s3api put-public-access-block --bucket ${name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
        reference: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
      });
    }

    // --- S3-001b: Bucket policy with Principal: "*" ---
    try {
      const policyResp = await s3.send(new GetBucketPolicyCommand({ Bucket: name }));
      if (policyResp.Policy) {
        const policy = JSON.parse(policyResp.Policy);
        for (const stmt of policy.Statement ?? []) {
          const principal = stmt.Principal;
          const isWildcard =
            principal === "*" ||
            principal?.AWS === "*" ||
            (Array.isArray(principal?.AWS) && principal.AWS.includes("*"));
          if (isWildcard && stmt.Effect === "Allow") {
            results.push({
              checkId: "S3-001",
              title: "Public bucket access - Wildcard bucket policy",
              severity: "CRITICAL",
              status: "FAIL",
              resource: arn,
              region,
              provider: "aws",
              details: `Bucket policy allows Principal:"*" with Effect:"Allow" — action: ${JSON.stringify(stmt.Action)}`,
              remediation: `aws s3api delete-bucket-policy --bucket ${name}  # or restrict the Principal`,
              reference: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html",
            });
          }
        }
      }
    } catch (err) {
      const code = (err as any).name ?? (err as any).Code;
      if (code !== "NoSuchBucketPolicy") {
        // Non-fatal, skip
      }
    }

    // --- S3-001c: ACL grants to AllUsers / AuthenticatedUsers ---
    try {
      const acl = await s3.send(new GetBucketAclCommand({ Bucket: name }));
      for (const grant of acl.Grants ?? []) {
        const uri = grant.Grantee?.URI ?? "";
        if (
          uri.includes("AllUsers") ||
          uri.includes("AuthenticatedUsers")
        ) {
          results.push({
            checkId: "S3-001",
            title: "Public bucket access - Public ACL grant",
            severity: "CRITICAL",
            status: "FAIL",
            resource: arn,
            region,
            provider: "aws",
            details: `Bucket ACL grants ${grant.Permission} to ${uri}`,
            remediation: `aws s3api put-bucket-acl --bucket ${name} --acl private`,
            reference: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
          });
        }
      }
    } catch {
      // Non-fatal
    }

    // If all checks passed for this bucket, record PASS
    const hasFail = results.some(
      (r) => r.resource === arn && r.checkId === "S3-001" && (r.status === "FAIL" || r.status === "ERROR"),
    );
    if (!hasFail) {
      results.push({
        checkId: "S3-001",
        title: "Public bucket access",
        severity: "CRITICAL",
        status: "PASS",
        resource: arn,
        region,
        provider: "aws",
        details: "Bucket has Block Public Access enabled, no wildcard policy, and no public ACL grants.",
        remediation: "No action required.",
      });
    }
  }

  return results;
}

/**
 * S3-002: Sensitive objects in S3 buckets
 */
export async function checkS3Objects(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const s3 = aws.s3(region);

  let buckets: { Name?: string }[] = [];
  try {
    const resp = await s3.send(new ListBucketsCommand({}));
    buckets = resp.Buckets ?? [];
  } catch (err) {
    results.push({
      checkId: "S3-002",
      title: "Sensitive objects in S3",
      severity: "HIGH",
      status: "ERROR",
      resource: "s3:*",
      region,
      provider: "aws",
      details: `Failed to list buckets: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: s3:ListAllMyBuckets",
    });
    return results;
  }

  for (const bucket of buckets) {
    const name = bucket.Name ?? "unknown";
    const arn = `arn:aws:s3:::${name}`;
    const sensitiveKeys: string[] = [];

    try {
      let continuationToken: string | undefined;
      let pageCount = 0;
      const maxPages = 5; // Limit pagination to avoid excessive API calls

      do {
        const resp = await s3.send(
          new ListObjectsV2Command({
            Bucket: name,
            MaxKeys: 1000,
            ContinuationToken: continuationToken,
          }),
        );

        for (const obj of resp.Contents ?? []) {
          const key = obj.Key ?? "";
          for (const pattern of SENSITIVE_PATTERNS) {
            if (pattern.test(key)) {
              sensitiveKeys.push(key);
              break;
            }
          }
        }

        continuationToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
        pageCount++;
      } while (continuationToken && pageCount < maxPages);

      if (sensitiveKeys.length > 0) {
        const displayKeys = sensitiveKeys.slice(0, 20);
        const extra = sensitiveKeys.length > 20 ? ` ... and ${sensitiveKeys.length - 20} more` : "";
        results.push({
          checkId: "S3-002",
          title: "Sensitive objects in S3",
          severity: "HIGH",
          status: "FAIL",
          resource: arn,
          region,
          provider: "aws",
          details: `Found ${sensitiveKeys.length} potentially sensitive object(s): ${displayKeys.join(", ")}${extra}`,
          remediation: "Review and remove sensitive files from S3. Use AWS Secrets Manager or Parameter Store for credentials. Enable server-side encryption.",
          reference: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
        });
      } else {
        results.push({
          checkId: "S3-002",
          title: "Sensitive objects in S3",
          severity: "HIGH",
          status: "PASS",
          resource: arn,
          region,
          provider: "aws",
          details: "No sensitive file patterns detected in object keys.",
          remediation: "No action required.",
        });
      }
    } catch (err) {
      const code = (err as any).name ?? (err as any).Code;
      if (code === "AccessDenied") {
        results.push({
          checkId: "S3-002",
          title: "Sensitive objects in S3",
          severity: "HIGH",
          status: "ERROR",
          resource: arn,
          region,
          provider: "aws",
          details: `Access denied listing objects in ${name}. Cannot check for sensitive files.`,
          remediation: "Verify IAM permissions: s3:ListBucket",
        });
      } else {
        results.push({
          checkId: "S3-002",
          title: "Sensitive objects in S3",
          severity: "HIGH",
          status: "ERROR",
          resource: arn,
          region,
          provider: "aws",
          details: `Error listing objects: ${(err as Error).message}`,
          remediation: "Check bucket permissions and region configuration.",
        });
      }
    }
  }

  return results;
}
