import type { AzureClientFactory } from "./client.js";
import type { CheckResult } from "../types/index.js";

interface VmArgs {
  resourceGroup?: string;
}

// Management ports that should never be exposed to 0.0.0.0/0
const MANAGEMENT_PORTS: Record<number, string> = {
  22: "SSH",
  3389: "RDP",
  5985: "WinRM HTTP",
  5986: "WinRM HTTPS",
};

/**
 * VM-001: Management ports exposed to internet (SSH, RDP, WinRM)
 * Checks NSG inbound rules for 0.0.0.0/0 or * on management ports
 */
export async function checkVmNetwork(
  azure: AzureClientFactory,
  args: VmArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const networkClient = azure.network();
  const subId = azure.getSubscriptionId();

  try {
    const nsgs = args.resourceGroup
      ? networkClient.networkSecurityGroups.list(args.resourceGroup)
      : networkClient.networkSecurityGroups.listAll();

    for await (const nsg of nsgs) {
      const nsgName = nsg.name || "unknown";
      const location = nsg.location || "unknown";
      const rg = extractResourceGroup(nsg.id);
      const allRules = [
        ...(nsg.securityRules || []),
        ...(nsg.defaultSecurityRules || []),
      ];

      // Only check inbound Allow rules
      const inboundAllowRules = allRules.filter(
        (r) =>
          r.direction === "Inbound" &&
          r.access === "Allow",
      );

      const exposedPorts: string[] = [];

      for (const rule of inboundAllowRules) {
        const isOpenSource =
          rule.sourceAddressPrefix === "*" ||
          rule.sourceAddressPrefix === "0.0.0.0/0" ||
          rule.sourceAddressPrefix === "Internet" ||
          (rule.sourceAddressPrefixes || []).some(
            (p) => p === "*" || p === "0.0.0.0/0" || p === "Internet",
          );

        if (!isOpenSource) continue;

        // Check if any management port is in the destination port range
        const destPorts = getDestinationPorts(rule);

        for (const [port, service] of Object.entries(MANAGEMENT_PORTS)) {
          const portNum = parseInt(port, 10);
          if (destPorts.includes(portNum)) {
            exposedPorts.push(
              `${service} (${port}) via rule '${rule.name || "unnamed"}' (priority ${rule.priority})`,
            );
          }
        }
      }

      if (exposedPorts.length > 0) {
        results.push({
          checkId: "VM-001",
          title: "Management ports exposed to internet",
          severity: "CRITICAL",
          status: "FAIL",
          resource: `${subId}/resourceGroups/${rg}/networkSecurityGroups/${nsgName}`,
          region: location,
          provider: "azure",
          details: `NSG '${nsgName}' allows inbound access from the internet (0.0.0.0/0) on management ports:\n${exposedPorts.map((p) => `  - ${p}`).join("\n")}`,
          remediation: `Restrict source addresses to specific IPs or use Azure Bastion for remote access:\naz network nsg rule update --resource-group ${rg} --nsg-name ${nsgName} --name <rule-name> --source-address-prefixes <your-ip>/32`,
          reference:
            "https://learn.microsoft.com/en-us/azure/virtual-machines/network-overview#network-security-groups",
        });
      } else {
        results.push({
          checkId: "VM-001",
          title: "Management ports exposed to internet",
          severity: "CRITICAL",
          status: "PASS",
          resource: `${subId}/resourceGroups/${rg}/networkSecurityGroups/${nsgName}`,
          region: location,
          provider: "azure",
          details: `NSG '${nsgName}' does not expose management ports (SSH, RDP, WinRM) to the internet.`,
          remediation: "No action required.",
        });
      }
    }
  } catch (err) {
    results.push({
      checkId: "VM-001",
      title: "Management ports exposed to internet",
      severity: "CRITICAL",
      status: "ERROR",
      resource: `${subId}/networkSecurityGroups`,
      region: "global",
      provider: "azure",
      details: `Failed to list NSGs: ${(err as Error).message}`,
      remediation: "Ensure the identity has Network Contributor or Reader role.",
    });
  }

  return results;
}

/**
 * VM-002: Unencrypted VM disks
 * VM-005: IMDS token theft exposure (informational)
 */
export async function checkVmEncryption(
  azure: AzureClientFactory,
  args: VmArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const computeClient = azure.compute();
  const subId = azure.getSubscriptionId();

  try {
    const vms = args.resourceGroup
      ? computeClient.virtualMachines.list(args.resourceGroup)
      : computeClient.virtualMachines.listAll();

    for await (const vm of vms) {
      const vmName = vm.name || "unknown";
      const location = vm.location || "unknown";
      const rg = extractResourceGroup(vm.id);

      // VM-002: Check disk encryption
      const unencryptedDisks: string[] = [];

      // Check OS disk
      const osDisk = vm.storageProfile?.osDisk;
      if (osDisk) {
        const osEncryption = osDisk.managedDisk?.securityProfile?.diskEncryptionSet ||
          osDisk.encryptionSettings?.enabled;
        // If the disk has a managed disk reference, check the disk resource
        if (osDisk.managedDisk?.id) {
          try {
            const diskName = osDisk.name || extractDiskName(osDisk.managedDisk.id);
            const disk = await computeClient.disks.get(rg, diskName);
            if (!disk.encryption?.type || disk.encryption.type === "EncryptionAtRestWithPlatformKey") {
              // Platform-managed keys are default but customer-managed is recommended
              // Only flag if no encryption at all is detected
              if (!disk.encryption?.type) {
                unencryptedDisks.push(`OS disk '${diskName}' (no encryption configured)`);
              }
            }
          } catch {
            // If we can't check the disk, check what we know from the VM profile
            if (!osEncryption) {
              unencryptedDisks.push(`OS disk '${osDisk.name || "unnamed"}' (encryption status unknown)`);
            }
          }
        }
      }

      // Check data disks
      for (const dataDisk of vm.storageProfile?.dataDisks || []) {
        if (dataDisk.managedDisk?.id) {
          try {
            const diskName = dataDisk.name || extractDiskName(dataDisk.managedDisk.id);
            const disk = await computeClient.disks.get(rg, diskName);
            if (!disk.encryption?.type) {
              unencryptedDisks.push(`Data disk '${diskName}' LUN ${dataDisk.lun} (no encryption configured)`);
            }
          } catch {
            // Skip if we can't read individual disk
          }
        }
      }

      if (unencryptedDisks.length > 0) {
        results.push({
          checkId: "VM-002",
          title: "Unencrypted VM disks",
          severity: "HIGH",
          status: "FAIL",
          resource: `${subId}/resourceGroups/${rg}/virtualMachines/${vmName}`,
          region: location,
          provider: "azure",
          details: `VM '${vmName}' has unencrypted disks:\n${unencryptedDisks.map((d) => `  - ${d}`).join("\n")}`,
          remediation: `Enable Azure Disk Encryption or server-side encryption with customer-managed keys:\naz vm encryption enable --resource-group ${rg} --name ${vmName} --disk-encryption-keyvault <keyvault-name>`,
          reference:
            "https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview",
        });
      } else {
        results.push({
          checkId: "VM-002",
          title: "Unencrypted VM disks",
          severity: "HIGH",
          status: "PASS",
          resource: `${subId}/resourceGroups/${rg}/virtualMachines/${vmName}`,
          region: location,
          provider: "azure",
          details: `VM '${vmName}' has encryption enabled on all disks.`,
          remediation: "No action required.",
        });
      }

      // VM-005: IMDS token theft exposure check
      const hasManagedIdentity =
        vm.identity?.type === "SystemAssigned" ||
        vm.identity?.type === "SystemAssigned, UserAssigned" ||
        vm.identity?.type === "UserAssigned";

      if (hasManagedIdentity) {
        results.push({
          checkId: "VM-005",
          title: "IMDS token theft exposure",
          severity: "INFO",
          status: "FAIL",
          resource: `${subId}/resourceGroups/${rg}/virtualMachines/${vmName}`,
          region: location,
          provider: "azure",
          details: `VM '${vmName}' has managed identity (${vm.identity?.type}) enabled. Any process on this VM can reach the IMDS endpoint (169.254.169.254) to obtain Azure AD tokens. If the VM is compromised, the attacker can use these tokens for lateral movement. Consider using Credential Guard and restricting IMDS access via firewall rules.`,
          remediation: `Restrict IMDS access to specific processes using iptables/Windows Firewall rules:\n# Linux: iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner <service-user> -j ACCEPT\n# iptables -A OUTPUT -d 169.254.169.254 -j DROP`,
          reference:
            "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token",
        });
      }
    }
  } catch (err) {
    results.push({
      checkId: "VM-002",
      title: "Unencrypted VM disks",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/virtualMachines`,
      region: "global",
      provider: "azure",
      details: `Failed to list virtual machines: ${(err as Error).message}`,
      remediation: "Ensure the identity has Virtual Machine Contributor or Reader role.",
    });
  }

  return results;
}

/**
 * VM-004: Over-privileged managed identities
 * Checks VMs with managed identity and their role assignments
 */
export async function checkVmIdentity(
  azure: AzureClientFactory,
  args: VmArgs = {},
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const computeClient = azure.compute();
  const authzClient = azure.authorization();
  const subId = azure.getSubscriptionId();

  // High-privilege built-in role definition IDs (suffix)
  const DANGEROUS_ROLES = new Map<string, string>([
    ["8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "Owner"],
    ["b24988ac-6180-42a0-ab88-20f7382dd24c", "Contributor"],
    ["18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", "User Access Administrator"],
  ]);

  try {
    const vms = args.resourceGroup
      ? computeClient.virtualMachines.list(args.resourceGroup)
      : computeClient.virtualMachines.listAll();

    for await (const vm of vms) {
      const vmName = vm.name || "unknown";
      const location = vm.location || "unknown";
      const rg = extractResourceGroup(vm.id);

      const hasManagedIdentity =
        vm.identity?.type === "SystemAssigned" ||
        vm.identity?.type === "SystemAssigned, UserAssigned" ||
        vm.identity?.type === "UserAssigned";

      if (!hasManagedIdentity) {
        results.push({
          checkId: "VM-004",
          title: "Over-privileged managed identity",
          severity: "HIGH",
          status: "PASS",
          resource: `${subId}/resourceGroups/${rg}/virtualMachines/${vmName}`,
          region: location,
          provider: "azure",
          details: `VM '${vmName}' does not have a managed identity assigned.`,
          remediation: "No action required.",
        });
        continue;
      }

      // Get the principal ID for the system-assigned identity
      const principalId = vm.identity?.principalId;
      const userIdentityPrincipalIds: string[] = [];

      // Collect user-assigned identity principal IDs
      if (vm.identity?.userAssignedIdentities) {
        for (const [, identity] of Object.entries(vm.identity.userAssignedIdentities)) {
          if (identity?.principalId) {
            userIdentityPrincipalIds.push(identity.principalId);
          }
        }
      }

      const allPrincipalIds = [
        ...(principalId ? [principalId] : []),
        ...userIdentityPrincipalIds,
      ];

      const dangerousAssignments: string[] = [];

      for (const pid of allPrincipalIds) {
        try {
          const scope = `/subscriptions/${subId}`;
          const assignments = authzClient.roleAssignments.listForScope(scope, {
            filter: `principalId eq '${pid}'`,
          });

          for await (const assignment of assignments) {
            const roleDefId = assignment.roleDefinitionId || "";
            // Extract the GUID from the role definition ID
            const roleGuid = roleDefId.split("/").pop() || "";

            if (DANGEROUS_ROLES.has(roleGuid)) {
              const roleName = DANGEROUS_ROLES.get(roleGuid)!;
              const assignmentScope = assignment.scope || "unknown";
              dangerousAssignments.push(
                `Role '${roleName}' at scope '${assignmentScope}' (principal: ${pid})`,
              );
            }
          }
        } catch {
          // May not have permission to list role assignments
        }
      }

      if (dangerousAssignments.length > 0) {
        results.push({
          checkId: "VM-004",
          title: "Over-privileged managed identity",
          severity: "HIGH",
          status: "FAIL",
          resource: `${subId}/resourceGroups/${rg}/virtualMachines/${vmName}`,
          region: location,
          provider: "azure",
          details: `VM '${vmName}' has managed identity with high-privilege role assignments:\n${dangerousAssignments.map((a) => `  - ${a}`).join("\n")}\nIf this VM is compromised, the attacker gains these privileges.`,
          remediation: `Apply least-privilege principle. Replace broad roles with specific roles scoped to required resources:\naz role assignment delete --assignee <principal-id> --role <role-name>\naz role assignment create --assignee <principal-id> --role <specific-role> --scope <narrow-scope>`,
          reference:
            "https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices",
        });
      } else {
        results.push({
          checkId: "VM-004",
          title: "Over-privileged managed identity",
          severity: "HIGH",
          status: "PASS",
          resource: `${subId}/resourceGroups/${rg}/virtualMachines/${vmName}`,
          region: location,
          provider: "azure",
          details: `VM '${vmName}' has managed identity without high-privilege role assignments (Owner, Contributor, User Access Administrator).`,
          remediation: "No action required.",
        });
      }
    }
  } catch (err) {
    results.push({
      checkId: "VM-004",
      title: "Over-privileged managed identity",
      severity: "HIGH",
      status: "ERROR",
      resource: `${subId}/virtualMachines`,
      region: "global",
      provider: "azure",
      details: `Failed to check VM identities: ${(err as Error).message}`,
      remediation: "Ensure the identity has Reader role on the subscription and permission to read role assignments.",
    });
  }

  return results;
}

function getDestinationPorts(rule: any): number[] {
  const ports: number[] = [];

  const addRange = (range: string) => {
    if (range === "*") {
      // All ports — add all management ports
      for (const port of Object.keys(MANAGEMENT_PORTS)) {
        ports.push(parseInt(port, 10));
      }
      return;
    }
    if (range.includes("-")) {
      const [start, end] = range.split("-").map(Number);
      for (const [port] of Object.entries(MANAGEMENT_PORTS)) {
        const portNum = parseInt(port, 10);
        if (portNum >= start && portNum <= end) {
          ports.push(portNum);
        }
      }
    } else {
      const portNum = parseInt(range, 10);
      if (!isNaN(portNum)) ports.push(portNum);
    }
  };

  if (rule.destinationPortRange) {
    addRange(rule.destinationPortRange);
  }
  if (rule.destinationPortRanges) {
    for (const range of rule.destinationPortRanges) {
      addRange(range);
    }
  }

  return ports;
}

function extractResourceGroup(resourceId?: string): string {
  if (!resourceId) return "unknown";
  const match = resourceId.match(/resourceGroups\/([^/]+)/i);
  return match ? match[1] : "unknown";
}

function extractDiskName(diskId: string): string {
  const parts = diskId.split("/");
  return parts[parts.length - 1] || "unknown";
}
