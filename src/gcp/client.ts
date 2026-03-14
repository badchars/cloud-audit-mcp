import { Storage } from "@google-cloud/storage";
import { InstancesClient, FirewallsClient } from "@google-cloud/compute";
import { ClusterManagerClient } from "@google-cloud/container";
import type { AuthStatus } from "../types/index.js";

export class GcpClientFactory {
  private projectId: string;
  private clients = new Map<string, any>();

  constructor() {
    this.projectId = process.env.GCP_PROJECT_ID || process.env.GCLOUD_PROJECT || process.env.GOOGLE_CLOUD_PROJECT || "";
    if (!this.projectId) {
      console.error("[cloud-audit] Warning: GCP_PROJECT_ID not set");
    }
  }

  private get<T>(key: string, Ctor: new (opts?: any) => T): T {
    if (!this.clients.has(key)) {
      this.clients.set(key, new Ctor());
    }
    return this.clients.get(key)! as T;
  }

  storage() { return this.get("storage", Storage); }
  instances() { return this.get("instances", InstancesClient); }
  firewalls() { return this.get("firewalls", FirewallsClient); }
  clusters() { return this.get("clusters", ClusterManagerClient); }

  getProjectId() { return this.projectId; }

  async getIdentity(): Promise<AuthStatus> {
    try {
      const storage = this.storage();
      // Test auth by listing a single bucket
      await storage.getBuckets({ maxResults: 1 });
      return { provider: "gcp", authenticated: true, account: this.projectId };
    } catch (err) {
      return { provider: "gcp", authenticated: false, error: (err as Error).message };
    }
  }
}
