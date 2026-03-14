import type { z } from "zod";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type CheckStatus = "PASS" | "FAIL" | "ERROR" | "NOT_APPLICABLE";
export type CloudProvider = "aws" | "azure" | "gcp";
export type Priority = "P0" | "P1" | "P2";

export interface CheckResult {
  checkId: string;
  title: string;
  severity: Severity;
  status: CheckStatus;
  resource: string;
  region: string;
  provider: CloudProvider;
  details: string;
  remediation: string;
  reference?: string;
}

export interface CheckMeta {
  id: string;
  provider: CloudProvider;
  title: string;
  severity: Severity;
  priority: Priority;
  description: string;
  references: string[];
}

export interface AuthStatus {
  provider: CloudProvider;
  authenticated: boolean;
  identity?: string;
  account?: string;
  region?: string;
  error?: string;
}

export interface ToolDef {
  name: string;
  description: string;
  schema: Record<string, z.ZodType>;
  execute: (args: any, ctx: ToolContext) => Promise<ToolResult>;
}

export interface ToolContext {
  getAwsClient: () => import("../aws/client.js").AwsClientFactory;
  getAzureClient: () => import("../azure/client.js").AzureClientFactory;
  getGcpClient: () => import("../gcp/client.js").GcpClientFactory;
  getFindings: () => CheckResult[];
  addFindings: (results: CheckResult[]) => void;
  clearFindings: () => void;
}

export interface ToolResult {
  content: { type: "text"; text: string }[];
}
