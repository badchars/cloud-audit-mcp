/**
 * MCP Tool Definitions — 38 tools across 4 categories.
 *
 * Each tool is defined with Zod schema and an executor function.
 */

import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";

// AWS check imports
import { checkS3Public, checkS3Objects } from "../aws/s3.js";
import { checkIamPolicies } from "../aws/iam.js";
import { checkEc2Imds, checkEc2Snapshots, checkEc2SecurityGroups } from "../aws/ec2.js";
import { checkLambdaEnv, checkLambdaPermissions } from "../aws/lambda.js";
import { checkEcrImages } from "../aws/ecr.js";
import { checkSecretsManager } from "../aws/secrets.js";
import { checkDynamodb } from "../aws/dynamodb.js";
import { checkApiGateway } from "../aws/apigw.js";
import { checkSageMaker } from "../aws/sagemaker.js";

// Azure check imports
import { checkStoragePublic, checkStorageSas } from "../azure/storage.js";
import { checkAutomation } from "../azure/automation.js";
import { checkVmNetwork, checkVmEncryption, checkVmIdentity } from "../azure/vm.js";
import { checkAdConsent } from "../azure/ad.js";
import { checkLogicApps } from "../azure/logic.js";
import { checkFunctions } from "../azure/functions.js";
import { checkKeyvault } from "../azure/keyvault.js";
import { checkAcr } from "../azure/acr.js";
import { checkSql } from "../azure/sql.js";
import { checkWebapp } from "../azure/webapp.js";

// GCP check imports
import { checkGcsPublic, checkGcsObjects } from "../gcp/storage.js";
import { checkMetadata } from "../gcp/metadata.js";
import { checkIamKeys, checkIamDelegation, checkIamCompute } from "../gcp/iam.js";
import { checkKubernetes } from "../gcp/kubernetes.js";
import { checkGcr } from "../gcp/gcr.js";

// Meta imports
import { listChecks } from "../meta/list-checks.js";
import { auditSummary } from "../meta/summary.js";
import { auditReport } from "../meta/report.js";
import { runAll } from "../meta/run-all.js";

function text(msg: string): ToolResult {
  return { content: [{ type: "text", text: msg }] };
}

function json(data: unknown): ToolResult {
  return text(JSON.stringify(data, null, 2));
}

export const allTools: ToolDef[] = [
  // ═══ AWS (13 tools) ═══

  {
    name: "aws_check_s3_public",
    description: "Check S3 buckets for public access via ACL, bucket policy, or missing Block Public Access. Detects S3-001.",
    schema: {
      region: z.string().optional().describe("AWS region (default: all regions)"),
      bucketName: z.string().optional().describe("Specific bucket name (default: all buckets)"),
    },
    execute: async (args, ctx) => {
      const results = await checkS3Public(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["S3-001"], total: results.length, pass: results.filter(r => r.status === "PASS").length, fail: results.filter(r => r.status === "FAIL").length, findings: results });
    },
  },
  {
    name: "aws_check_s3_objects",
    description: "Scan S3 bucket objects for sensitive files (SSH keys, SQL dumps, .env, credentials). Detects S3-002, S3-003.",
    schema: {
      region: z.string().optional().describe("AWS region"),
      bucketName: z.string().optional().describe("Specific bucket name (default: all buckets)"),
      maxObjects: z.number().optional().describe("Max objects to scan per bucket (default: 1000)"),
    },
    execute: async (args, ctx) => {
      const results = await checkS3Objects(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["S3-002", "S3-003"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_iam_policies",
    description: "Check IAM policies for privilege escalation paths: policy version abuse, dangerous permission combos (PassRole+CreateFunction), admin Lambda roles. Detects IAM-001, IAM-002, IAM-003.",
    schema: {
      region: z.string().optional().describe("AWS region"),
    },
    execute: async (args, ctx) => {
      const results = await checkIamPolicies(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["IAM-001", "IAM-002", "IAM-003"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_ec2_imds",
    description: "Check EC2 instances for IMDSv1 enabled (credential theft via SSRF). Detects EC2-001.",
    schema: {
      region: z.string().optional().describe("AWS region (default: configured region)"),
    },
    execute: async (args, ctx) => {
      const results = await checkEc2Imds(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["EC2-001"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_ec2_snapshots",
    description: "Check EBS snapshots for encryption and public access. Detects EC2-002.",
    schema: {
      region: z.string().optional().describe("AWS region"),
    },
    execute: async (args, ctx) => {
      const results = await checkEc2Snapshots(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["EC2-002"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_ec2_security_groups",
    description: "Check security groups for unrestricted inbound access (0.0.0.0/0). Detects EC2-003.",
    schema: {
      region: z.string().optional().describe("AWS region"),
    },
    execute: async (args, ctx) => {
      const results = await checkEc2SecurityGroups(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["EC2-003"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_lambda_env",
    description: "Scan Lambda function environment variables for hardcoded secrets (API keys, passwords, tokens). Detects LAMBDA-001.",
    schema: {
      region: z.string().optional().describe("AWS region"),
    },
    execute: async (args, ctx) => {
      const results = await checkLambdaEnv(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["LAMBDA-001"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_lambda_permissions",
    description: "Check for UpdateFunctionCode permissions and event source mapping bypass. Detects LAMBDA-002, LAMBDA-003.",
    schema: {
      region: z.string().optional().describe("AWS region"),
    },
    execute: async (args, ctx) => {
      const results = await checkLambdaPermissions(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["LAMBDA-002", "LAMBDA-003"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_ecr_images",
    description: "Check ECR repositories for image scan findings and scan configuration. Detects ECR-001, ECR-002.",
    schema: {
      region: z.string().optional().describe("AWS region"),
    },
    execute: async (args, ctx) => {
      const results = await checkEcrImages(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ECR-001", "ECR-002"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_secrets_manager",
    description: "Check Secrets Manager resource policies for overly broad access. Detects SM-001.",
    schema: {
      region: z.string().optional().describe("AWS region"),
    },
    execute: async (args, ctx) => {
      const results = await checkSecretsManager(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SM-001"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_dynamodb",
    description: "Check DynamoDB tables for encryption and stream configurations. Detects DYNAMO-001, DYNAMO-002.",
    schema: {
      region: z.string().optional().describe("AWS region"),
    },
    execute: async (args, ctx) => {
      const results = await checkDynamodb(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["DYNAMO-001", "DYNAMO-002"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_api_gateway",
    description: "Check API Gateway REST APIs for missing authentication. Detects APIGW-001.",
    schema: {
      region: z.string().optional().describe("AWS region"),
    },
    execute: async (args, ctx) => {
      const results = await checkApiGateway(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["APIGW-001"], total: results.length, findings: results });
    },
  },
  {
    name: "aws_check_sagemaker",
    description: "Check SageMaker notebook instances for direct internet access and root access. Detects SAGE-001.",
    schema: {
      region: z.string().optional().describe("AWS region"),
    },
    execute: async (args, ctx) => {
      const results = await checkSageMaker(ctx.getAwsClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SAGE-001"], total: results.length, findings: results });
    },
  },

  // ═══ Azure (13 tools) ═══

  {
    name: "azure_check_storage_public",
    description: "Check Azure Storage accounts for public blob access and container public access levels. Detects STOR-001, STOR-002.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkStoragePublic(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["STOR-001", "STOR-002"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_storage_sas",
    description: "Check Azure Storage for long-lived SAS tokens. Detects STOR-003.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkStorageSas(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["STOR-003"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_automation",
    description: "Check Azure Automation for hardcoded credentials in runbooks, DSC plaintext passwords, unencrypted variables. Detects AUTO-001, AUTO-002, AUTO-003.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkAutomation(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["AUTO-001", "AUTO-002", "AUTO-003"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_vm_network",
    description: "Check NSGs for exposed management ports (SSH 22, RDP 3389, WinRM 5985-5986) from internet. Detects VM-001.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkVmNetwork(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["VM-001"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_vm_encryption",
    description: "Check VM disks for encryption at rest. Detects VM-002.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkVmEncryption(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["VM-002"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_vm_identity",
    description: "Check VMs with managed identities for over-privileged role assignments and IMDS exposure. Detects VM-004, VM-005.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkVmIdentity(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["VM-004", "VM-005"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_ad_consent",
    description: "Check Azure AD for secrets in object descriptions and user consent settings. Detects AAD-001, AAD-002. Note: requires Microsoft Graph API.",
    schema: {},
    execute: async (args, ctx) => {
      const results = await checkAdConsent(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["AAD-001", "AAD-002"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_logic_apps",
    description: "Check Logic Apps with HTTP triggers and managed identity for SSRF risk. Detects LOGIC-001.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkLogicApps(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["LOGIC-001"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_functions",
    description: "Check Azure Functions for anonymous auth level and Key Vault references. Detects FUNC-001, FUNC-002.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkFunctions(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["FUNC-001", "FUNC-002"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_keyvault",
    description: "Check Key Vaults for overly permissive access policies and unrestricted network access. Detects KV-001, KV-002.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkKeyvault(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["KV-001", "KV-002"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_acr",
    description: "Check Azure Container Registry for admin user enabled and image security. Detects ACR-001, ACR-002.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkAcr(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACR-001", "ACR-002"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_sql",
    description: "Check Azure SQL servers for SQL authentication and overly permissive firewall rules. Detects SQL-001, SQL-002.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkSql(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SQL-001", "SQL-002"], total: results.length, findings: results });
    },
  },
  {
    name: "azure_check_webapp",
    description: "Check Azure Web Apps for SCM auth, connection string credentials, and deployment security. Detects WEBAPP-001, WEBAPP-002, WEBAPP-003.",
    schema: {
      resourceGroup: z.string().optional().describe("Resource group name (default: all)"),
    },
    execute: async (args, ctx) => {
      const results = await checkWebapp(ctx.getAzureClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["WEBAPP-001", "WEBAPP-002", "WEBAPP-003"], total: results.length, findings: results });
    },
  },

  // ═══ GCP (8 tools) ═══

  {
    name: "gcp_check_gcs_public",
    description: "Check GCS buckets for public access (allUsers/allAuthenticatedUsers IAM bindings). Detects GCS-001.",
    schema: {},
    execute: async (args, ctx) => {
      const results = await checkGcsPublic(ctx.getGcpClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["GCS-001"], total: results.length, findings: results });
    },
  },
  {
    name: "gcp_check_gcs_objects",
    description: "Scan GCS buckets for sensitive files (SA keys, SQL dumps, .env files). Detects GCS-002, GCS-003.",
    schema: {
      bucketName: z.string().optional().describe("Specific bucket name (default: all buckets)"),
      maxObjects: z.number().optional().describe("Max objects to scan per bucket (default: 1000)"),
    },
    execute: async (args, ctx) => {
      const results = await checkGcsObjects(ctx.getGcpClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["GCS-002", "GCS-003"], total: results.length, findings: results });
    },
  },
  {
    name: "gcp_check_metadata",
    description: "Check GCE instances for startup script secrets, cloud-platform scope, and metadata concealment. Detects META-001, META-002, META-003.",
    schema: {
      zone: z.string().optional().describe("GCP zone (default: all zones)"),
    },
    execute: async (args, ctx) => {
      const results = await checkMetadata(ctx.getGcpClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["META-001", "META-002", "META-003"], total: results.length, findings: results });
    },
  },
  {
    name: "gcp_check_iam_keys",
    description: "Audit service account keys for age, usage, and user-managed keys. Detects IAM-001g.",
    schema: {},
    execute: async (args, ctx) => {
      const results = await checkIamKeys(ctx.getGcpClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["IAM-001g"], total: results.length, findings: results });
    },
  },
  {
    name: "gcp_check_iam_delegation",
    description: "Detect service account impersonation chains and Token Creator role abuse. Detects IAM-002g, IAM-003g.",
    schema: {},
    execute: async (args, ctx) => {
      const results = await checkIamDelegation(ctx.getGcpClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["IAM-002g", "IAM-003g"], total: results.length, findings: results });
    },
  },
  {
    name: "gcp_check_iam_compute",
    description: "Check for setMetadata permission enabling SSH key injection on instances. Detects IAM-004g.",
    schema: {},
    execute: async (args, ctx) => {
      const results = await checkIamCompute(ctx.getGcpClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["IAM-004g"], total: results.length, findings: results });
    },
  },
  {
    name: "gcp_check_kubernetes",
    description: "Check GKE clusters for default SA cluster-admin, privileged containers, kubelet exposure. Detects K8S-001, K8S-002, K8S-003, K8S-004.",
    schema: {
      location: z.string().optional().describe("GKE cluster location (default: all locations)"),
    },
    execute: async (args, ctx) => {
      const results = await checkKubernetes(ctx.getGcpClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["K8S-001", "K8S-002", "K8S-003", "K8S-004"], total: results.length, findings: results });
    },
  },
  {
    name: "gcp_check_gcr",
    description: "Check for unexpected/hidden images in Google Container Registry. Detects GCR-001.",
    schema: {},
    execute: async (args, ctx) => {
      const results = await checkGcr(ctx.getGcpClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["GCR-001"], total: results.length, findings: results });
    },
  },

  // ═══ Meta (4 tools) ═══

  {
    name: "cloud_list_checks",
    description: "List all available security checks with their ID, severity, priority, and description. Filter by provider, severity, or priority.",
    schema: {
      provider: z.enum(["aws", "azure", "gcp"]).optional().describe("Filter by cloud provider"),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).optional().describe("Filter by severity"),
      priority: z.enum(["P0", "P1", "P2"]).optional().describe("Filter by priority (P0=critical, P1=high, P2=medium)"),
    },
    execute: async (args) => {
      const checks = listChecks(args);
      return json({ total: checks.length, checks });
    },
  },
  {
    name: "cloud_audit_summary",
    description: "Get a summary of all findings from the current session, grouped by provider, severity, and status.",
    schema: {},
    execute: async (_, ctx) => {
      const summary = auditSummary(ctx.getFindings());
      return json(summary);
    },
  },
  {
    name: "cloud_audit_report",
    description: "Generate a markdown or JSON report from all findings in the current session.",
    schema: {
      title: z.string().optional().describe("Report title"),
      format: z.enum(["markdown", "json"]).optional().describe("Output format (default: markdown)"),
      severityFilter: z.array(z.string()).optional().describe("Filter by severity levels (e.g. ['CRITICAL', 'HIGH'])"),
    },
    execute: async (args, ctx) => {
      const report = auditReport(ctx.getFindings(), args);
      return text(report);
    },
  },
  {
    name: "cloud_run_all",
    description: "Run all security checks for a specific cloud provider. Returns combined results.",
    schema: {
      provider: z.enum(["aws", "azure", "gcp"]).describe("Cloud provider to audit"),
      region: z.string().optional().describe("Limit to specific region"),
    },
    execute: async (args, ctx) => {
      const results = await runAll(args.provider, ctx, { region: args.region });
      const summary = auditSummary(results);
      return json({
        provider: args.provider,
        totalChecks: results.length,
        pass: summary.byStatus.pass,
        fail: summary.byStatus.fail,
        error: summary.byStatus.error,
        criticalFindings: summary.criticalFindings.length,
        findings: results,
      });
    },
  },
];
