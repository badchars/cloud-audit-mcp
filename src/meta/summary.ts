import type { CheckResult, CloudProvider, Severity } from "../types/index.js";

export interface AuditSummary {
  totalFindings: number;
  byStatus: { pass: number; fail: number; error: number };
  byProvider: Record<string, { pass: number; fail: number; error: number }>;
  bySeverity: Record<string, number>;
  criticalFindings: CheckResult[];
  topRemediation: { action: string; count: number }[];
}

export function auditSummary(findings: CheckResult[]): AuditSummary {
  const byStatus = { pass: 0, fail: 0, error: 0 };
  const byProvider: Record<string, { pass: number; fail: number; error: number }> = {};
  const bySeverity: Record<string, number> = {};
  const remediationMap = new Map<string, number>();

  for (const f of findings) {
    // Status counts
    if (f.status === "PASS") byStatus.pass++;
    else if (f.status === "FAIL") byStatus.fail++;
    else if (f.status === "ERROR") byStatus.error++;

    // Provider breakdown
    if (!byProvider[f.provider]) byProvider[f.provider] = { pass: 0, fail: 0, error: 0 };
    if (f.status === "PASS") byProvider[f.provider].pass++;
    else if (f.status === "FAIL") byProvider[f.provider].fail++;
    else if (f.status === "ERROR") byProvider[f.provider].error++;

    // Severity breakdown (only for FAIL)
    if (f.status === "FAIL") {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    }

    // Remediation grouping
    if (f.status === "FAIL" && f.remediation) {
      const key = f.remediation.split("\n")[0].trim();
      remediationMap.set(key, (remediationMap.get(key) || 0) + 1);
    }
  }

  const criticalFindings = findings.filter(
    f => f.status === "FAIL" && (f.severity === "CRITICAL" || f.severity === "HIGH")
  );

  const topRemediation = Array.from(remediationMap.entries())
    .map(([action, count]) => ({ action, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    totalFindings: findings.length,
    byStatus,
    byProvider,
    bySeverity,
    criticalFindings,
    topRemediation,
  };
}
