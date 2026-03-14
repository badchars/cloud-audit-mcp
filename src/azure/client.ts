import { DefaultAzureCredential } from "@azure/identity";
import { StorageManagementClient } from "@azure/arm-storage";
import { ComputeManagementClient } from "@azure/arm-compute";
import { NetworkManagementClient } from "@azure/arm-network";
import { AutomationClient } from "@azure/arm-automation";
import { LogicManagementClient } from "@azure/arm-logic";
import { WebSiteManagementClient } from "@azure/arm-appservice";
import { KeyVaultManagementClient } from "@azure/arm-keyvault";
import { ContainerRegistryManagementClient } from "@azure/arm-containerregistry";
import { SqlManagementClient } from "@azure/arm-sql";
import { AuthorizationManagementClient } from "@azure/arm-authorization";
import { ResourceManagementClient } from "@azure/arm-resources";
import type { AuthStatus } from "../types/index.js";

export class AzureClientFactory {
  private subscriptionId: string;
  private credential: DefaultAzureCredential;
  private clients = new Map<string, any>();

  constructor() {
    this.subscriptionId = process.env.AZURE_SUBSCRIPTION_ID || "";
    if (!this.subscriptionId) {
      console.error("[cloud-audit] Warning: AZURE_SUBSCRIPTION_ID not set");
    }
    this.credential = new DefaultAzureCredential();
  }

  private get<T>(key: string, Ctor: new (cred: any, subId: string) => T): T {
    if (!this.clients.has(key)) {
      this.clients.set(key, new Ctor(this.credential, this.subscriptionId));
    }
    return this.clients.get(key)! as T;
  }

  storage() { return this.get("storage", StorageManagementClient); }
  compute() { return this.get("compute", ComputeManagementClient); }
  network() { return this.get("network", NetworkManagementClient); }
  automation() {
    if (!this.clients.has("automation")) {
      this.clients.set("automation", new AutomationClient(this.credential, this.subscriptionId, "status"));
    }
    return this.clients.get("automation")! as AutomationClient;
  }
  logic() { return this.get("logic", LogicManagementClient); }
  appService() { return this.get("appservice", WebSiteManagementClient); }
  keyVault() { return this.get("keyvault", KeyVaultManagementClient); }
  containerRegistry() { return this.get("acr", ContainerRegistryManagementClient); }
  sql() { return this.get("sql", SqlManagementClient); }
  authorization() { return this.get("authz", AuthorizationManagementClient); }
  resources() { return this.get("resources", ResourceManagementClient); }

  getSubscriptionId() { return this.subscriptionId; }

  async getIdentity(): Promise<AuthStatus> {
    try {
      const token = await this.credential.getToken("https://management.azure.com/.default");
      return {
        provider: "azure",
        authenticated: true,
        account: this.subscriptionId,
        identity: token ? "authenticated" : undefined,
      };
    } catch (err) {
      return { provider: "azure", authenticated: false, error: (err as Error).message };
    }
  }
}
