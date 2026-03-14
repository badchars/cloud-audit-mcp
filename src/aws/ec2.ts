import {
  DescribeInstancesCommand,
  DescribeSnapshotsCommand,
  DescribeSnapshotAttributeCommand,
  DescribeSecurityGroupsCommand,
} from "@aws-sdk/client-ec2";
import type { CheckResult } from "../types/index.js";
import type { AwsClientFactory } from "./client.js";

// Well-known dangerous ports
const DANGEROUS_PORTS: Record<number, string> = {
  22: "SSH",
  3389: "RDP",
  3306: "MySQL",
  5432: "PostgreSQL",
  1433: "MSSQL",
  27017: "MongoDB",
  6379: "Redis",
  9200: "Elasticsearch",
  11211: "Memcached",
  5900: "VNC",
  23: "Telnet",
  445: "SMB",
  135: "RPC",
};

/**
 * EC2-001: IMDSv1 enabled (credential theft risk)
 */
export async function checkEc2Imds(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const ec2 = aws.ec2(region);

  try {
    let nextToken: string | undefined;
    let instanceCount = 0;

    do {
      const resp = await ec2.send(
        new DescribeInstancesCommand({ NextToken: nextToken, MaxResults: 100 }),
      );

      for (const reservation of resp.Reservations ?? []) {
        for (const instance of reservation.Instances ?? []) {
          instanceCount++;
          const instanceId = instance.InstanceId ?? "unknown";
          const nameTag = instance.Tags?.find((t) => t.Key === "Name")?.Value ?? "";
          const resource = nameTag ? `${instanceId} (${nameTag})` : instanceId;
          const state = instance.State?.Name;

          // Skip terminated instances
          if (state === "terminated" || state === "shutting-down") continue;

          const httpTokens = instance.MetadataOptions?.HttpTokens;
          const httpEndpoint = instance.MetadataOptions?.HttpEndpoint;

          if (httpEndpoint === "disabled") {
            results.push({
              checkId: "EC2-001",
              title: "Instance Metadata Service check",
              severity: "HIGH",
              status: "PASS",
              resource,
              region,
              provider: "aws",
              details: "IMDS is disabled on this instance.",
              remediation: "No action required.",
            });
            continue;
          }

          if (httpTokens !== "required") {
            results.push({
              checkId: "EC2-001",
              title: "IMDSv1 enabled - credential theft risk",
              severity: "HIGH",
              status: "FAIL",
              resource,
              region,
              provider: "aws",
              details: `Instance ${instanceId} has IMDSv1 enabled (HttpTokens=${httpTokens ?? "optional"}). An attacker with SSRF can steal IAM credentials from http://169.254.169.254/latest/meta-data/iam/security-credentials/.`,
              remediation: `aws ec2 modify-instance-metadata-options --instance-id ${instanceId} --http-tokens required --http-endpoint enabled`,
              reference: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
            });
          } else {
            results.push({
              checkId: "EC2-001",
              title: "Instance Metadata Service check",
              severity: "HIGH",
              status: "PASS",
              resource,
              region,
              provider: "aws",
              details: "IMDSv2 is enforced (HttpTokens=required).",
              remediation: "No action required.",
            });
          }
        }
      }

      nextToken = resp.NextToken;
    } while (nextToken);

    if (instanceCount === 0) {
      results.push({
        checkId: "EC2-001",
        title: "IMDSv1 check",
        severity: "HIGH",
        status: "PASS",
        resource: "ec2:instances",
        region,
        provider: "aws",
        details: "No EC2 instances found in this region.",
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "EC2-001",
      title: "IMDSv1 check",
      severity: "HIGH",
      status: "ERROR",
      resource: "ec2:instances",
      region,
      provider: "aws",
      details: `Failed to describe instances: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: ec2:DescribeInstances",
    });
  }

  return results;
}

/**
 * EC2-002: Unencrypted or public EBS snapshots
 */
export async function checkEc2Snapshots(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const ec2 = aws.ec2(region);

  try {
    let nextToken: string | undefined;
    let snapshotCount = 0;

    do {
      const resp = await ec2.send(
        new DescribeSnapshotsCommand({
          OwnerIds: ["self"],
          NextToken: nextToken,
          MaxResults: 200,
        }),
      );

      for (const snapshot of resp.Snapshots ?? []) {
        snapshotCount++;
        const snapId = snapshot.SnapshotId ?? "unknown";
        const resource = `arn:aws:ec2:${region}::snapshot/${snapId}`;

        // Check encryption
        if (!snapshot.Encrypted) {
          results.push({
            checkId: "EC2-002",
            title: "Unencrypted EBS snapshot",
            severity: "MEDIUM",
            status: "FAIL",
            resource,
            region,
            provider: "aws",
            details: `Snapshot ${snapId} (${snapshot.VolumeSize ?? "?"}GB, Volume: ${snapshot.VolumeId ?? "?"}) is not encrypted. Data can be read by anyone with snapshot access.`,
            remediation: `Copy the snapshot with encryption enabled:\naws ec2 copy-snapshot --source-snapshot-id ${snapId} --source-region ${region} --encrypted --kms-key-id alias/aws/ebs`,
            reference: "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html",
          });
        }

        // Check if snapshot is publicly shared
        try {
          const attrResp = await ec2.send(
            new DescribeSnapshotAttributeCommand({
              SnapshotId: snapId,
              Attribute: "createVolumePermission",
            }),
          );

          const isPublic = (attrResp.CreateVolumePermissions ?? []).some(
            (p) => p.Group === "all",
          );

          if (isPublic) {
            results.push({
              checkId: "EC2-002",
              title: "Publicly shared EBS snapshot",
              severity: "CRITICAL",
              status: "FAIL",
              resource,
              region,
              provider: "aws",
              details: `Snapshot ${snapId} is publicly shared. Any AWS account can create a volume from this snapshot and read its data.`,
              remediation: `aws ec2 modify-snapshot-attribute --snapshot-id ${snapId} --attribute createVolumePermission --operation-type remove --group-names all`,
              reference: "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html",
            });
          }
        } catch {
          // Non-fatal
        }

        // Check if this snapshot passed all checks
        const hasFail = results.some(
          (r) => r.resource === resource && r.status === "FAIL",
        );
        if (!hasFail) {
          results.push({
            checkId: "EC2-002",
            title: "EBS snapshot security check",
            severity: "MEDIUM",
            status: "PASS",
            resource,
            region,
            provider: "aws",
            details: `Snapshot ${snapId} is encrypted and not publicly shared.`,
            remediation: "No action required.",
          });
        }
      }

      nextToken = resp.NextToken;
    } while (nextToken);

    if (snapshotCount === 0) {
      results.push({
        checkId: "EC2-002",
        title: "EBS snapshot security",
        severity: "MEDIUM",
        status: "PASS",
        resource: "ec2:snapshots",
        region,
        provider: "aws",
        details: "No EBS snapshots found in this region.",
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "EC2-002",
      title: "EBS snapshot security",
      severity: "MEDIUM",
      status: "ERROR",
      resource: "ec2:snapshots",
      region,
      provider: "aws",
      details: `Failed to describe snapshots: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: ec2:DescribeSnapshots",
    });
  }

  return results;
}

/**
 * EC2-003: Security groups with 0.0.0.0/0 ingress
 */
export async function checkEc2SecurityGroups(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const ec2 = aws.ec2(region);

  try {
    let nextToken: string | undefined;
    let sgCount = 0;

    do {
      const resp = await ec2.send(
        new DescribeSecurityGroupsCommand({ NextToken: nextToken, MaxResults: 100 }),
      );

      for (const sg of resp.SecurityGroups ?? []) {
        sgCount++;
        const sgId = sg.GroupId ?? "unknown";
        const sgName = sg.GroupName ?? "";
        const vpcId = sg.VpcId ?? "no-vpc";
        const resource = `${sgId} (${sgName}, VPC: ${vpcId})`;
        let hasFinding = false;

        for (const rule of sg.IpPermissions ?? []) {
          const fromPort = rule.FromPort ?? 0;
          const toPort = rule.ToPort ?? 65535;
          const protocol = rule.IpProtocol ?? "-1";

          // Check IPv4 ranges
          for (const range of rule.IpRanges ?? []) {
            if (range.CidrIp === "0.0.0.0/0") {
              const portRange = protocol === "-1" ? "ALL" : `${fromPort}-${toPort}`;
              const dangerousPorts = getDangerousPorts(fromPort, toPort, protocol);
              const severity = protocol === "-1" || dangerousPorts.length > 0 ? "CRITICAL" : "HIGH";

              results.push({
                checkId: "EC2-003",
                title: "Security group allows 0.0.0.0/0 ingress",
                severity,
                status: "FAIL",
                resource,
                region,
                provider: "aws",
                details: `SG ${sgId} allows inbound ${protocol === "-1" ? "ALL traffic" : `${protocol.toUpperCase()} port ${portRange}`} from 0.0.0.0/0.${dangerousPorts.length > 0 ? ` Exposed services: ${dangerousPorts.join(", ")}.` : ""}`,
                remediation: `aws ec2 revoke-security-group-ingress --group-id ${sgId} --protocol ${protocol === "-1" ? "-1" : protocol} ${protocol !== "-1" ? `--port ${fromPort === toPort ? fromPort : `${fromPort}-${toPort}`}` : ""} --cidr 0.0.0.0/0`,
                reference: "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
              });
              hasFinding = true;
            }
          }

          // Check IPv6 ranges
          for (const range of rule.Ipv6Ranges ?? []) {
            if (range.CidrIpv6 === "::/0") {
              const portRange = protocol === "-1" ? "ALL" : `${fromPort}-${toPort}`;
              const dangerousPorts = getDangerousPorts(fromPort, toPort, protocol);
              const severity = protocol === "-1" || dangerousPorts.length > 0 ? "CRITICAL" : "HIGH";

              results.push({
                checkId: "EC2-003",
                title: "Security group allows ::/0 ingress",
                severity,
                status: "FAIL",
                resource,
                region,
                provider: "aws",
                details: `SG ${sgId} allows inbound ${protocol === "-1" ? "ALL traffic" : `${protocol.toUpperCase()} port ${portRange}`} from ::/0 (IPv6).${dangerousPorts.length > 0 ? ` Exposed services: ${dangerousPorts.join(", ")}.` : ""}`,
                remediation: `aws ec2 revoke-security-group-ingress --group-id ${sgId} --ip-permissions IpProtocol=${protocol === "-1" ? "-1" : protocol},${protocol !== "-1" ? `FromPort=${fromPort},ToPort=${toPort},` : ""}Ipv6Ranges='[{"CidrIpv6":"::/0"}]'`,
                reference: "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
              });
              hasFinding = true;
            }
          }
        }

        if (!hasFinding) {
          results.push({
            checkId: "EC2-003",
            title: "Security group ingress check",
            severity: "HIGH",
            status: "PASS",
            resource,
            region,
            provider: "aws",
            details: `Security group ${sgId} has no 0.0.0.0/0 or ::/0 ingress rules.`,
            remediation: "No action required.",
          });
        }
      }

      nextToken = resp.NextToken;
    } while (nextToken);

    if (sgCount === 0) {
      results.push({
        checkId: "EC2-003",
        title: "Security group ingress check",
        severity: "HIGH",
        status: "PASS",
        resource: "ec2:security-groups",
        region,
        provider: "aws",
        details: "No security groups found in this region.",
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "EC2-003",
      title: "Security group ingress check",
      severity: "HIGH",
      status: "ERROR",
      resource: "ec2:security-groups",
      region,
      provider: "aws",
      details: `Failed to describe security groups: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: ec2:DescribeSecurityGroups",
    });
  }

  return results;
}

function getDangerousPorts(fromPort: number, toPort: number, protocol: string): string[] {
  if (protocol === "-1") {
    return Object.entries(DANGEROUS_PORTS).map(([p, name]) => `${p}/${name}`);
  }
  const found: string[] = [];
  for (const [portStr, name] of Object.entries(DANGEROUS_PORTS)) {
    const port = parseInt(portStr, 10);
    if (port >= fromPort && port <= toPort) {
      found.push(`${port}/${name}`);
    }
  }
  return found;
}
