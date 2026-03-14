import {
  ListFunctionsCommand,
  GetFunctionCommand,
  ListEventSourceMappingsCommand,
} from "@aws-sdk/client-lambda";
import type { CheckResult } from "../types/index.js";
import type { AwsClientFactory } from "./client.js";

// Patterns that indicate secrets in environment variable names
const SECRET_KEY_PATTERNS = [
  /password/i,
  /secret/i,
  /api[_-]?key/i,
  /access[_-]?key/i,
  /private[_-]?key/i,
  /token/i,
  /auth/i,
  /credential/i,
  /connection[_-]?string/i,
  /database[_-]?url/i,
  /db[_-]?pass/i,
];

// Patterns that indicate secrets in environment variable values
const SECRET_VALUE_PATTERNS = [
  /^AKIA[0-9A-Z]{16}$/,                  // AWS Access Key ID
  /^[A-Za-z0-9/+=]{40}$/,                // AWS Secret Access Key (40 chars)
  /^ghp_[A-Za-z0-9]{36}$/,               // GitHub Personal Access Token
  /^sk-[A-Za-z0-9]{48}/,                 // OpenAI API Key
  /^xox[bprs]-[A-Za-z0-9-]+/,            // Slack tokens
  /-----BEGIN (RSA )?PRIVATE KEY-----/,   // PEM private keys
];

// Environment variables that are expected and safe to have
const SAFE_ENV_VARS = new Set([
  "AWS_LAMBDA_FUNCTION_NAME",
  "AWS_LAMBDA_FUNCTION_VERSION",
  "AWS_LAMBDA_LOG_GROUP_NAME",
  "AWS_LAMBDA_LOG_STREAM_NAME",
  "AWS_REGION",
  "AWS_DEFAULT_REGION",
  "AWS_EXECUTION_ENV",
  "LAMBDA_TASK_ROOT",
  "LAMBDA_RUNTIME_DIR",
  "TZ",
  "LANG",
  "PATH",
  "LD_LIBRARY_PATH",
  "NODE_PATH",
  "PYTHONPATH",
  "GEM_PATH",
  "_HANDLER",
  "_X_AMZN_TRACE_ID",
  "AWS_XRAY_DAEMON_ADDRESS",
  "AWS_XRAY_CONTEXT_MISSING",
]);

/**
 * LAMBDA-001: Secrets in Lambda environment variables
 */
export async function checkLambdaEnv(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const lambda = aws.lambda(region);

  try {
    let marker: string | undefined;
    let functionCount = 0;

    do {
      const resp = await lambda.send(
        new ListFunctionsCommand({ Marker: marker, MaxItems: 50 }),
      );

      for (const fn of resp.Functions ?? []) {
        functionCount++;
        const fnName = fn.FunctionName ?? "unknown";
        const fnArn = fn.FunctionArn ?? `arn:aws:lambda:${region}:*:function:${fnName}`;
        const envVars = fn.Environment?.Variables ?? {};
        const suspiciousVars: { key: string; reason: string }[] = [];

        for (const [key, value] of Object.entries(envVars)) {
          if (SAFE_ENV_VARS.has(key)) continue;

          // Check key name patterns
          for (const pattern of SECRET_KEY_PATTERNS) {
            if (pattern.test(key)) {
              suspiciousVars.push({
                key,
                reason: `Key name matches secret pattern: ${pattern.source}`,
              });
              break;
            }
          }

          // Check value patterns
          if (value) {
            for (const pattern of SECRET_VALUE_PATTERNS) {
              if (pattern.test(value)) {
                suspiciousVars.push({
                  key,
                  reason: `Value matches known credential format (${pattern.source.slice(0, 30)}...)`,
                });
                break;
              }
            }
          }
        }

        if (suspiciousVars.length > 0) {
          const varList = suspiciousVars
            .map((v) => `  - ${v.key}: ${v.reason}`)
            .join("\n");
          results.push({
            checkId: "LAMBDA-001",
            title: "Secrets in Lambda environment variables",
            severity: "CRITICAL",
            status: "FAIL",
            resource: fnArn,
            region,
            provider: "aws",
            details: `Function "${fnName}" has ${suspiciousVars.length} potential secret(s) in environment variables:\n${varList}\n\nPlaintext secrets in env vars are visible in the Lambda console, API, and CloudTrail logs.`,
            remediation: `Move secrets to AWS Secrets Manager or SSM Parameter Store:\naws secretsmanager create-secret --name "${fnName}/secret" --secret-string "VALUE"\nThen reference via AWS SDK in function code instead of env vars.`,
            reference: "https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html",
          });
        } else {
          results.push({
            checkId: "LAMBDA-001",
            title: "Lambda environment variables check",
            severity: "CRITICAL",
            status: "PASS",
            resource: fnArn,
            region,
            provider: "aws",
            details: `Function "${fnName}" has no suspicious secrets in environment variables.`,
            remediation: "No action required.",
          });
        }
      }

      marker = resp.NextMarker;
    } while (marker);

    if (functionCount === 0) {
      results.push({
        checkId: "LAMBDA-001",
        title: "Lambda environment variables check",
        severity: "CRITICAL",
        status: "PASS",
        resource: "lambda:functions",
        region,
        provider: "aws",
        details: "No Lambda functions found in this region.",
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "LAMBDA-001",
      title: "Lambda environment variables check",
      severity: "CRITICAL",
      status: "ERROR",
      resource: "lambda:functions",
      region,
      provider: "aws",
      details: `Failed to list functions: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: lambda:ListFunctions, lambda:GetFunction",
    });
  }

  return results;
}

/**
 * LAMBDA-002: Lambda function configuration review (UpdateFunctionCode risk)
 * LAMBDA-003: Event source mapping audit
 */
export async function checkLambdaPermissions(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const lambda = aws.lambda(region);

  // --- LAMBDA-002: Check function configs for risky patterns ---
  try {
    let marker: string | undefined;
    let functionCount = 0;

    do {
      const resp = await lambda.send(
        new ListFunctionsCommand({ Marker: marker, MaxItems: 50 }),
      );

      for (const fn of resp.Functions ?? []) {
        functionCount++;
        const fnName = fn.FunctionName ?? "unknown";
        const fnArn = fn.FunctionArn ?? `arn:aws:lambda:${region}:*:function:${fnName}`;
        const findings: string[] = [];

        // Check for overly permissive role (role name heuristic)
        const role = fn.Role ?? "";
        if (role.includes("admin") || role.includes("Admin") || role.includes("FullAccess")) {
          findings.push(`Execution role appears overly permissive: ${role.split("/").pop()}`);
        }

        // Check for no VPC configuration (function runs in AWS public network)
        if (!fn.VpcConfig?.VpcId) {
          findings.push("Function is not deployed in a VPC — has unrestricted internet access");
        }

        // Check runtime end-of-life
        const runtime = fn.Runtime ?? "";
        const deprecatedRuntimes = [
          "nodejs12.x", "nodejs14.x", "nodejs16.x",
          "python3.6", "python3.7", "python3.8",
          "dotnetcore3.1", "dotnet6",
          "ruby2.7",
          "java8", "java8.al2",
          "go1.x",
        ];
        if (deprecatedRuntimes.includes(runtime)) {
          findings.push(`Runtime "${runtime}" is deprecated or approaching end-of-life`);
        }

        // Check code package size (unusually large = potential supply chain risk)
        const codeSize = fn.CodeSize ?? 0;
        if (codeSize > 100 * 1024 * 1024) {
          findings.push(`Unusually large code package: ${(codeSize / 1024 / 1024).toFixed(1)}MB`);
        }

        if (findings.length > 0) {
          results.push({
            checkId: "LAMBDA-002",
            title: "Lambda function configuration risk",
            severity: "MEDIUM",
            status: "FAIL",
            resource: fnArn,
            region,
            provider: "aws",
            details: `Function "${fnName}" has configuration concerns:\n${findings.map((f) => `  - ${f}`).join("\n")}`,
            remediation: `Review and harden function configuration:\n- Apply least-privilege IAM role\n- Deploy in VPC if accessing internal resources\n- Update deprecated runtimes\naws lambda get-function --function-name ${fnName}`,
            reference: "https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html",
          });
        } else {
          results.push({
            checkId: "LAMBDA-002",
            title: "Lambda function configuration check",
            severity: "MEDIUM",
            status: "PASS",
            resource: fnArn,
            region,
            provider: "aws",
            details: `Function "${fnName}" configuration looks reasonable.`,
            remediation: "No action required.",
          });
        }
      }

      marker = resp.NextMarker;
    } while (marker);

    if (functionCount === 0) {
      results.push({
        checkId: "LAMBDA-002",
        title: "Lambda function configuration check",
        severity: "MEDIUM",
        status: "PASS",
        resource: "lambda:functions",
        region,
        provider: "aws",
        details: "No Lambda functions found in this region.",
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "LAMBDA-002",
      title: "Lambda function configuration check",
      severity: "MEDIUM",
      status: "ERROR",
      resource: "lambda:functions",
      region,
      provider: "aws",
      details: `Failed to list functions: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: lambda:ListFunctions",
    });
  }

  // --- LAMBDA-003: Event source mappings ---
  try {
    let marker: string | undefined;
    let mappingCount = 0;

    do {
      const resp = await lambda.send(
        new ListEventSourceMappingsCommand({ Marker: marker, MaxItems: 100 }),
      );

      for (const mapping of resp.EventSourceMappings ?? []) {
        mappingCount++;
        const uuid = mapping.UUID ?? "unknown";
        const fnArn = mapping.FunctionArn ?? "unknown";
        const eventSource = mapping.EventSourceArn ?? "unknown";
        const state = mapping.State ?? "unknown";
        const resource = `${uuid} (${fnArn.split(":").pop()})`;
        const findings: string[] = [];

        // Check if mapping is enabled for potentially sensitive sources
        if (state === "Enabled" || state === "Creating" || state === "Updating") {
          if (eventSource.includes(":dynamodb:")) {
            findings.push(`Active DynamoDB stream trigger: ${eventSource.split("/").pop()} — data changes flow to Lambda`);
          }
          if (eventSource.includes(":kinesis:")) {
            findings.push(`Active Kinesis stream trigger: ${eventSource.split("/").pop()} — stream data flows to Lambda`);
          }
          if (eventSource.includes(":sqs:")) {
            findings.push(`Active SQS trigger: ${eventSource.split("/").pop()}`);
          }
          if (eventSource.includes(":kafka:") || eventSource.includes(":msk:")) {
            findings.push(`Active Kafka/MSK trigger: ${eventSource.split("/").pop()}`);
          }
        }

        // Check for disabled error handling (no DLQ/destination)
        if (!mapping.DestinationConfig?.OnFailure?.Destination) {
          findings.push("No failure destination configured — failed events may be silently dropped");
        }

        if (findings.length > 0) {
          results.push({
            checkId: "LAMBDA-003",
            title: "Lambda event source mapping audit",
            severity: "MEDIUM",
            status: "FAIL",
            resource,
            region,
            provider: "aws",
            details: `Event source mapping ${uuid}:\n${findings.map((f) => `  - ${f}`).join("\n")}`,
            remediation: `Review event source mappings and ensure least-privilege:\naws lambda get-event-source-mapping --uuid ${uuid}\nConsider adding failure destinations and reviewing function permissions.`,
            reference: "https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html",
          });
        } else {
          results.push({
            checkId: "LAMBDA-003",
            title: "Lambda event source mapping check",
            severity: "MEDIUM",
            status: "PASS",
            resource,
            region,
            provider: "aws",
            details: "Event source mapping configuration looks reasonable.",
            remediation: "No action required.",
          });
        }
      }

      marker = resp.NextMarker;
    } while (marker);

    if (mappingCount === 0) {
      results.push({
        checkId: "LAMBDA-003",
        title: "Lambda event source mapping check",
        severity: "MEDIUM",
        status: "PASS",
        resource: "lambda:event-source-mappings",
        region,
        provider: "aws",
        details: "No event source mappings found in this region.",
        remediation: "No action required.",
      });
    }
  } catch (err) {
    results.push({
      checkId: "LAMBDA-003",
      title: "Lambda event source mapping check",
      severity: "MEDIUM",
      status: "ERROR",
      resource: "lambda:event-source-mappings",
      region,
      provider: "aws",
      details: `Failed to list event source mappings: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: lambda:ListEventSourceMappings",
    });
  }

  return results;
}
