import {
  ListTablesCommand,
  DescribeTableCommand,
} from "@aws-sdk/client-dynamodb";
import type { CheckResult } from "../types/index.js";
import type { AwsClientFactory } from "./client.js";

/**
 * DYNAMO-001: Encryption at rest check
 * DYNAMO-002: DynamoDB streams enabled (data flow audit)
 */
export async function checkDynamodb(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const ddb = aws.dynamodb(region);

  let tableNames: string[] = [];

  try {
    let lastEvaluatedTableName: string | undefined;

    do {
      const resp = await ddb.send(
        new ListTablesCommand({
          ExclusiveStartTableName: lastEvaluatedTableName,
          Limit: 100,
        }),
      );
      tableNames.push(...(resp.TableNames ?? []));
      lastEvaluatedTableName = resp.LastEvaluatedTableName;
    } while (lastEvaluatedTableName);
  } catch (err) {
    results.push({
      checkId: "DYNAMO-001",
      title: "DynamoDB encryption at rest",
      severity: "HIGH",
      status: "ERROR",
      resource: "dynamodb:tables",
      region,
      provider: "aws",
      details: `Failed to list tables: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: dynamodb:ListTables",
    });
    return results;
  }

  if (tableNames.length === 0) {
    results.push({
      checkId: "DYNAMO-001",
      title: "DynamoDB encryption at rest",
      severity: "HIGH",
      status: "PASS",
      resource: "dynamodb:tables",
      region,
      provider: "aws",
      details: "No DynamoDB tables found in this region.",
      remediation: "No action required.",
    });
    return results;
  }

  for (const tableName of tableNames) {
    const tableArn = `arn:aws:dynamodb:${region}:*:table/${tableName}`;

    try {
      const resp = await ddb.send(
        new DescribeTableCommand({ TableName: tableName }),
      );
      const table = resp.Table;
      if (!table) continue;

      const actualArn = table.TableArn ?? tableArn;

      // --- DYNAMO-001: Encryption at rest ---
      const sseDescription = table.SSEDescription;
      const sseStatus = sseDescription?.Status;
      const sseType = sseDescription?.SSEType;

      // DynamoDB tables are always encrypted with AWS owned key by default (no SSEDescription present)
      // Customer-managed (KMS) or AWS-managed KMS shows SSEDescription
      if (!sseDescription) {
        // Default encryption (AWS owned key) — technically encrypted but not with customer-controlled key
        results.push({
          checkId: "DYNAMO-001",
          title: "DynamoDB using default AWS owned encryption",
          severity: "LOW",
          status: "FAIL",
          resource: actualArn,
          region,
          provider: "aws",
          details: `Table "${tableName}" uses the default AWS owned key for encryption. While encrypted, you have no control over key rotation, access policies, or audit logging for the encryption key.`,
          remediation: `Enable AWS managed or customer managed KMS encryption:\naws dynamodb update-table --table-name ${tableName} --sse-specification Enabled=true,SSEType=KMS`,
          reference: "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
        });
      } else if (sseStatus === "ENABLED" || sseStatus === "ENABLING") {
        results.push({
          checkId: "DYNAMO-001",
          title: "DynamoDB encryption at rest",
          severity: "HIGH",
          status: "PASS",
          resource: actualArn,
          region,
          provider: "aws",
          details: `Table "${tableName}" is encrypted with ${sseType ?? "KMS"} key (Status: ${sseStatus}).${sseDescription.KMSMasterKeyArn ? ` Key: ${sseDescription.KMSMasterKeyArn}` : ""}`,
          remediation: "No action required.",
        });
      } else {
        results.push({
          checkId: "DYNAMO-001",
          title: "DynamoDB encryption issue",
          severity: "HIGH",
          status: "FAIL",
          resource: actualArn,
          region,
          provider: "aws",
          details: `Table "${tableName}" SSE status is "${sseStatus}". Encryption may not be properly configured.`,
          remediation: `Enable KMS encryption:\naws dynamodb update-table --table-name ${tableName} --sse-specification Enabled=true,SSEType=KMS`,
          reference: "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
        });
      }

      // --- DYNAMO-002: DynamoDB streams ---
      const streamSpec = table.StreamSpecification;
      const latestStreamArn = table.LatestStreamArn;

      if (streamSpec?.StreamEnabled) {
        const streamViewType = streamSpec.StreamViewType ?? "UNKNOWN";
        const findings: string[] = [];

        // NEW_AND_OLD_IMAGES captures full data — highest risk
        if (streamViewType === "NEW_AND_OLD_IMAGES") {
          findings.push("Stream captures BOTH old and new item images — full data exposure to consumers");
        } else if (streamViewType === "NEW_IMAGE") {
          findings.push("Stream captures new item images — data flows to stream consumers");
        } else if (streamViewType === "OLD_IMAGE") {
          findings.push("Stream captures old item images — previous data flows to stream consumers");
        } else if (streamViewType === "KEYS_ONLY") {
          findings.push("Stream captures key attributes only — minimal data exposure");
        }

        const severity = streamViewType === "NEW_AND_OLD_IMAGES" ? "MEDIUM" : "LOW";

        results.push({
          checkId: "DYNAMO-002",
          title: "DynamoDB stream enabled",
          severity,
          status: "FAIL",
          resource: actualArn,
          region,
          provider: "aws",
          details: `Table "${tableName}" has DynamoDB Streams enabled (ViewType: ${streamViewType}).\n${findings.map((f) => `  - ${f}`).join("\n")}${latestStreamArn ? `\n  - Stream ARN: ${latestStreamArn}` : ""}\n\nEnsure stream consumers (Lambda triggers, Kinesis) are authorized and necessary.`,
          remediation: `Review stream consumers:\naws dynamodbstreams describe-stream --stream-arn ${latestStreamArn ?? `<stream-arn>`}\n\nTo disable streams:\naws dynamodb update-table --table-name ${tableName} --stream-specification StreamEnabled=false`,
          reference: "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html",
        });
      } else {
        results.push({
          checkId: "DYNAMO-002",
          title: "DynamoDB streams check",
          severity: "MEDIUM",
          status: "PASS",
          resource: actualArn,
          region,
          provider: "aws",
          details: `Table "${tableName}" does not have DynamoDB Streams enabled.`,
          remediation: "No action required.",
        });
      }
    } catch (err) {
      results.push({
        checkId: "DYNAMO-001",
        title: "DynamoDB table check",
        severity: "HIGH",
        status: "ERROR",
        resource: tableArn,
        region,
        provider: "aws",
        details: `Failed to describe table "${tableName}": ${(err as Error).message}`,
        remediation: "Verify IAM permissions: dynamodb:DescribeTable",
      });
    }
  }

  return results;
}
