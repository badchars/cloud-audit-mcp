import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { S3Client } from "@aws-sdk/client-s3";
import { IAMClient } from "@aws-sdk/client-iam";
import { EC2Client } from "@aws-sdk/client-ec2";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { ECRClient } from "@aws-sdk/client-ecr";
import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { APIGatewayClient } from "@aws-sdk/client-api-gateway";
import { SageMakerClient } from "@aws-sdk/client-sagemaker";
import type { AuthStatus } from "../types/index.js";

export class AwsClientFactory {
  private region: string;
  private clients = new Map<string, any>();

  constructor(region?: string) {
    this.region = region || process.env.AWS_DEFAULT_REGION || process.env.AWS_REGION || "us-east-1";
  }

  private get<T>(key: string, Ctor: new (cfg: { region: string }) => T, region?: string): T {
    const r = region || this.region;
    const k = `${key}:${r}`;
    if (!this.clients.has(k)) this.clients.set(k, new Ctor({ region: r }));
    return this.clients.get(k)! as T;
  }

  s3(region?: string) { return this.get("s3", S3Client, region); }
  iam() { return this.get("iam", IAMClient, "us-east-1"); }
  ec2(region?: string) { return this.get("ec2", EC2Client, region); }
  lambda(region?: string) { return this.get("lambda", LambdaClient, region); }
  ecr(region?: string) { return this.get("ecr", ECRClient, region); }
  secretsManager(region?: string) { return this.get("sm", SecretsManagerClient, region); }
  dynamodb(region?: string) { return this.get("ddb", DynamoDBClient, region); }
  apiGateway(region?: string) { return this.get("apigw", APIGatewayClient, region); }
  sageMaker(region?: string) { return this.get("sage", SageMakerClient, region); }

  getRegion() { return this.region; }

  async getIdentity(): Promise<AuthStatus> {
    try {
      const sts = this.get("sts", STSClient);
      const id = await sts.send(new GetCallerIdentityCommand({}));
      return { provider: "aws", authenticated: true, identity: id.Arn, account: id.Account, region: this.region };
    } catch (err) {
      return { provider: "aws", authenticated: false, error: (err as Error).message };
    }
  }
}
