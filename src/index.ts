import { startMcpStdio } from "./protocol/mcp-server.js";
import { AwsClientFactory } from "./aws/client.js";
import { AzureClientFactory } from "./azure/client.js";
import { GcpClientFactory } from "./gcp/client.js";
import type { ToolContext, CheckResult } from "./types/index.js";

// Global state
let findings: CheckResult[] = [];
let awsClient: AwsClientFactory | null = null;
let azureClient: AzureClientFactory | null = null;
let gcpClient: GcpClientFactory | null = null;

function buildToolContext(): ToolContext {
  return {
    getAwsClient: () => {
      if (!awsClient) awsClient = new AwsClientFactory();
      return awsClient;
    },
    getAzureClient: () => {
      if (!azureClient) azureClient = new AzureClientFactory();
      return azureClient;
    },
    getGcpClient: () => {
      if (!gcpClient) gcpClient = new GcpClientFactory();
      return gcpClient;
    },
    getFindings: () => findings,
    addFindings: (results) => { findings.push(...results); },
    clearFindings: () => { findings = []; },
  };
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    console.log(`cloud-audit-mcp — Cloud security audit tools for AI agents

Usage:
  bun run src/index.ts [options]

Options:
  --help, -h  Show this help

Environment:
  AWS:   AWS_PROFILE, AWS_DEFAULT_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  Azure: AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
  GCP:   GOOGLE_APPLICATION_CREDENTIALS, GCP_PROJECT_ID
`);
    return;
  }

  const ctx = buildToolContext();

  process.on("SIGINT", () => {
    console.error("[cloud-audit] Shutting down...");
    process.exit(0);
  });

  console.error("[cloud-audit] Starting MCP server (stdio)...");
  await startMcpStdio(ctx);
  await new Promise(() => {});
}

main();
