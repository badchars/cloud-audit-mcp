import type { CheckResult } from "../types/index.js";
import type { GcpClientFactory } from "./client.js";

/**
 * K8S-001: Default SA with cluster-admin / legacy ABAC enabled
 * K8S-002: Privileged containers allowed (PodSecurityPolicy / Binary Authorization)
 * K8S-003: Kubelet API / Secure Boot not enabled
 * K8S-004: SA token automount (informational)
 */
export async function checkKubernetes(
  gcp: GcpClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const project = gcp.getProjectId();
  const clustersClient = gcp.clusters();

  let clusters: any[];
  try {
    const [response] = await clustersClient.listClusters({
      parent: `projects/${project}/locations/-`,
    });
    clusters = response.clusters ?? [];
  } catch (err) {
    results.push({
      checkId: "K8S-001",
      title: "GKE cluster security audit",
      severity: "CRITICAL",
      status: "ERROR",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: `Failed to list GKE clusters: ${(err as Error).message}`,
      remediation: "Verify Application Default Credentials and container.clusters.list permission.",
    });
    return results;
  }

  if (clusters.length === 0) {
    results.push({
      checkId: "K8S-001",
      title: "GKE cluster security audit",
      severity: "CRITICAL",
      status: "NOT_APPLICABLE",
      resource: `projects/${project}`,
      region: "global",
      provider: "gcp",
      details: "No GKE clusters found in the project.",
      remediation: "No action required.",
    });
    return results;
  }

  for (const cluster of clusters) {
    const clusterName: string = cluster.name ?? "unknown";
    const location: string = cluster.location ?? cluster.zone ?? "unknown";
    const resource = `projects/${project}/locations/${location}/clusters/${clusterName}`;

    // --- K8S-001: Legacy ABAC enabled ---
    const legacyAbac = cluster.legacyAbac?.enabled === true;
    if (legacyAbac) {
      results.push({
        checkId: "K8S-001",
        title: "Legacy ABAC enabled",
        severity: "CRITICAL",
        status: "FAIL",
        resource,
        region: location,
        provider: "gcp",
        details: "Legacy Attribute-Based Access Control (ABAC) is enabled. ABAC is deprecated and allows overly broad access. Any authenticated user can access all resources without fine-grained RBAC rules.",
        remediation: `Disable legacy ABAC and use RBAC instead:\ngcloud container clusters update ${clusterName} --zone=${location} --no-enable-legacy-authorization`,
        reference: "https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled",
      });
    } else {
      results.push({
        checkId: "K8S-001",
        title: "Legacy ABAC disabled",
        severity: "CRITICAL",
        status: "PASS",
        resource,
        region: location,
        provider: "gcp",
        details: "Legacy ABAC is disabled. Cluster uses RBAC for access control.",
        remediation: "No action required.",
      });
    }

    // --- K8S-001b: Client certificate authentication ---
    const masterAuth = cluster.masterAuth ?? {};
    const clientCertEnabled =
      masterAuth.clientCertificateConfig?.issueClientCertificate === true ||
      !!masterAuth.clientCertificate;

    if (clientCertEnabled) {
      results.push({
        checkId: "K8S-001",
        title: "Client certificate authentication enabled",
        severity: "HIGH",
        status: "FAIL",
        resource,
        region: location,
        provider: "gcp",
        details: "Client certificate authentication is enabled. Client certificates cannot be revoked and provide persistent cluster access.",
        remediation: "Disable client certificate issuance. Use gcloud or OIDC-based authentication instead. Client certificates cannot be disabled on existing clusters; create a new cluster without them.",
        reference: "https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods",
      });
    }

    // --- K8S-001c: Workload Identity disabled ---
    const workloadIdentityConfig = cluster.workloadIdentityConfig;
    const hasWorkloadIdentity = !!workloadIdentityConfig?.workloadPool;

    if (!hasWorkloadIdentity) {
      results.push({
        checkId: "K8S-001",
        title: "Workload Identity not enabled",
        severity: "HIGH",
        status: "FAIL",
        resource,
        region: location,
        provider: "gcp",
        details: "Workload Identity is not enabled. Pods may use the node's service account with broad permissions instead of dedicated per-pod identities.",
        remediation: `Enable Workload Identity:\ngcloud container clusters update ${clusterName} --zone=${location} --workload-pool=${project}.svc.id.goog`,
        reference: "https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity",
      });
    } else {
      results.push({
        checkId: "K8S-001",
        title: "Workload Identity enabled",
        severity: "HIGH",
        status: "PASS",
        resource,
        region: location,
        provider: "gcp",
        details: `Workload Identity is enabled with pool: ${workloadIdentityConfig.workloadPool}`,
        remediation: "No action required.",
      });
    }

    // --- K8S-002: Pod Security / Binary Authorization ---
    const binaryAuthorization = cluster.binaryAuthorization;
    const hasBinAuthz =
      binaryAuthorization?.enabled === true ||
      binaryAuthorization?.evaluationMode === "PROJECT_SINGLETON_POLICY_ENFORCE";

    // Check for PodSecurityPolicy (deprecated) or Pod Security Standards
    const podSecurityPolicy = cluster.podSecurityPolicyConfig?.enabled === true;

    if (!hasBinAuthz && !podSecurityPolicy) {
      results.push({
        checkId: "K8S-002",
        title: "Privileged containers allowed",
        severity: "HIGH",
        status: "FAIL",
        resource,
        region: location,
        provider: "gcp",
        details: "Neither Binary Authorization nor PodSecurityPolicy is enabled. Privileged containers can be deployed without restrictions.",
        remediation: `Enable Binary Authorization to control container deployments:\ngcloud container clusters update ${clusterName} --zone=${location} --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE\n\nAlternatively, use Kubernetes Pod Security Standards (PSS) with admission controller.`,
        reference: "https://cloud.google.com/binary-authorization/docs/overview",
      });
    } else {
      const method = hasBinAuthz ? "Binary Authorization" : "PodSecurityPolicy";
      results.push({
        checkId: "K8S-002",
        title: "Container deployment controls",
        severity: "HIGH",
        status: "PASS",
        resource,
        region: location,
        provider: "gcp",
        details: `${method} is enabled to control container deployments.`,
        remediation: "No action required.",
      });
    }

    // --- K8S-003: Secure Boot / Shielded nodes ---
    const nodePools = cluster.nodePools ?? [];
    for (const pool of nodePools) {
      const poolName: string = pool.name ?? "default-pool";
      const poolResource = `${resource}/nodePools/${poolName}`;
      const shieldedConfig = pool.config?.shieldedInstanceConfig;
      const secureBootEnabled = shieldedConfig?.enableSecureBoot === true;
      const integrityMonitoring = shieldedConfig?.enableIntegrityMonitoring === true;

      if (!secureBootEnabled) {
        results.push({
          checkId: "K8S-003",
          title: "Secure Boot not enabled on node pool",
          severity: "MEDIUM",
          status: "FAIL",
          resource: poolResource,
          region: location,
          provider: "gcp",
          details: `Node pool "${poolName}" does not have Secure Boot enabled. Without Secure Boot, node boot integrity cannot be verified and rootkits may persist.`,
          remediation: `Enable Shielded GKE Nodes with Secure Boot. This requires creating a new node pool:\ngcloud container node-pools create ${poolName}-secure --cluster=${clusterName} --zone=${location} --shielded-secure-boot --shielded-integrity-monitoring`,
          reference: "https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes",
        });
      } else {
        results.push({
          checkId: "K8S-003",
          title: "Secure Boot enabled on node pool",
          severity: "MEDIUM",
          status: "PASS",
          resource: poolResource,
          region: location,
          provider: "gcp",
          details: `Node pool "${poolName}" has Secure Boot${integrityMonitoring ? " and Integrity Monitoring" : ""} enabled.`,
          remediation: "No action required.",
        });
      }
    }

    // --- K8S-004: Service account token automount (informational) ---
    // GKE automatically mounts SA tokens. With Workload Identity, this is the
    // GCP SA token. Without it, it's the Compute Engine default SA token.
    if (!hasWorkloadIdentity) {
      results.push({
        checkId: "K8S-004",
        title: "SA token automount without Workload Identity",
        severity: "MEDIUM",
        status: "FAIL",
        resource,
        region: location,
        provider: "gcp",
        details: "Service account tokens are automatically mounted in pods. Without Workload Identity, pods use the node's Compute Engine service account, which may have broad permissions.",
        remediation: `1. Enable Workload Identity (see K8S-001 remediation)\n2. Set automountServiceAccountToken: false in pod specs where SA access is not needed\n3. Use dedicated KSAs mapped to minimal GSAs`,
        reference: "https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity",
      });
    } else {
      results.push({
        checkId: "K8S-004",
        title: "SA token automount with Workload Identity",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        region: location,
        provider: "gcp",
        details: "Workload Identity is enabled. SA token automount uses scoped GCP identities rather than the node's broad Compute Engine SA.",
        remediation: "Ensure each namespace KSA is mapped to a dedicated GSA with minimal permissions.",
      });
    }

    // --- K8S extra: Network Policy ---
    const networkPolicy = cluster.networkPolicy?.enabled === true;
    const networkConfig = cluster.networkConfig;
    const datapathProvider = networkConfig?.datapathProvider;
    const hasDataplanev2 = datapathProvider === "ADVANCED_DATAPATH";

    if (!networkPolicy && !hasDataplanev2) {
      results.push({
        checkId: "K8S-002",
        title: "Network Policy not enabled",
        severity: "MEDIUM",
        status: "FAIL",
        resource,
        region: location,
        provider: "gcp",
        details: "Network Policy is not enabled. Pods can communicate with any other pod in the cluster without restrictions (flat network).",
        remediation: `Enable Network Policy (Calico) or Dataplane V2:\ngcloud container clusters update ${clusterName} --zone=${location} --enable-network-policy`,
        reference: "https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy",
      });
    }
  }

  return results;
}
