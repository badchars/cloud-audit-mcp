import {
  GetRestApisCommand,
  GetResourcesCommand,
  GetMethodCommand,
} from "@aws-sdk/client-api-gateway";
import type { CheckResult } from "../types/index.js";
import type { AwsClientFactory } from "./client.js";

/**
 * APIGW-001: API Gateway methods without authentication
 */
export async function checkApiGateway(
  aws: AwsClientFactory,
  _args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const region = aws.getRegion();
  const apigw = aws.apiGateway(region);

  let apis: { id?: string; name?: string; description?: string }[] = [];

  try {
    let position: string | undefined;

    do {
      const resp = await apigw.send(
        new GetRestApisCommand({ position, limit: 100 }),
      );
      apis.push(...(resp.items ?? []));
      position = resp.position;
    } while (position);
  } catch (err) {
    results.push({
      checkId: "APIGW-001",
      title: "API Gateway authentication check",
      severity: "HIGH",
      status: "ERROR",
      resource: "apigateway:rest-apis",
      region,
      provider: "aws",
      details: `Failed to list REST APIs: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: apigateway:GET",
    });
    return results;
  }

  if (apis.length === 0) {
    results.push({
      checkId: "APIGW-001",
      title: "API Gateway authentication check",
      severity: "HIGH",
      status: "PASS",
      resource: "apigateway:rest-apis",
      region,
      provider: "aws",
      details: "No REST APIs found in this region.",
      remediation: "No action required.",
    });
    return results;
  }

  for (const api of apis) {
    const apiId = api.id ?? "unknown";
    const apiName = api.name ?? "unknown";
    const apiArn = `arn:aws:apigateway:${region}::/restapis/${apiId}`;

    // Get all resources for this API
    let resources: {
      id?: string;
      path?: string;
      resourceMethods?: Record<string, any>;
    }[] = [];

    try {
      let position: string | undefined;

      do {
        const resp = await apigw.send(
          new GetResourcesCommand({
            restApiId: apiId,
            position,
            limit: 100,
          }),
        );
        resources.push(...(resp.items ?? []));
        position = resp.position;
      } while (position);
    } catch (err) {
      results.push({
        checkId: "APIGW-001",
        title: "API Gateway authentication check",
        severity: "HIGH",
        status: "ERROR",
        resource: apiArn,
        region,
        provider: "aws",
        details: `Failed to get resources for API "${apiName}": ${(err as Error).message}`,
        remediation: "Verify IAM permissions: apigateway:GET on resources",
      });
      continue;
    }

    const unauthMethods: { path: string; method: string; authType: string }[] = [];
    let totalMethods = 0;

    for (const resource of resources) {
      const path = resource.path ?? "/";
      const methods = resource.resourceMethods ?? {};

      for (const httpMethod of Object.keys(methods)) {
        // Skip OPTIONS (CORS preflight)
        if (httpMethod === "OPTIONS") continue;
        totalMethods++;

        try {
          const methodResp = await apigw.send(
            new GetMethodCommand({
              restApiId: apiId,
              resourceId: resource.id!,
              httpMethod,
            }),
          );

          const authType = methodResp.authorizationType ?? "NONE";
          const apiKeyRequired = methodResp.apiKeyRequired ?? false;

          if (authType === "NONE" && !apiKeyRequired) {
            unauthMethods.push({ path, method: httpMethod, authType });
          }
        } catch (err) {
          // GetMethod can fail for mock integrations or permissions
          const code = (err as any).name ?? (err as any).Code;
          if (code !== "NotFoundException") {
            // Non-fatal, skip this method
          }
        }
      }
    }

    if (unauthMethods.length > 0) {
      const methodList = unauthMethods
        .slice(0, 20)
        .map((m) => `  - ${m.method} ${m.path}`)
        .join("\n");
      const extra = unauthMethods.length > 20
        ? `\n  ... and ${unauthMethods.length - 20} more`
        : "";

      results.push({
        checkId: "APIGW-001",
        title: "API Gateway methods without authentication",
        severity: "HIGH",
        status: "FAIL",
        resource: apiArn,
        region,
        provider: "aws",
        details: `API "${apiName}" (${apiId}) has ${unauthMethods.length}/${totalMethods} method(s) without authentication:\n${methodList}${extra}\n\nThese endpoints are publicly accessible without any authorization.`,
        remediation: `Add authentication to API methods. Options:\n1. IAM authorization:\n   aws apigateway update-method --rest-api-id ${apiId} --resource-id <resource-id> --http-method <METHOD> --patch-operations op=replace,path=/authorizationType,value=AWS_IAM\n2. Cognito authorizer\n3. Lambda authorizer\n4. API key requirement`,
        reference: "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html",
      });
    } else if (totalMethods > 0) {
      results.push({
        checkId: "APIGW-001",
        title: "API Gateway authentication check",
        severity: "HIGH",
        status: "PASS",
        resource: apiArn,
        region,
        provider: "aws",
        details: `API "${apiName}" (${apiId}) — all ${totalMethods} method(s) have authentication configured.`,
        remediation: "No action required.",
      });
    } else {
      results.push({
        checkId: "APIGW-001",
        title: "API Gateway authentication check",
        severity: "HIGH",
        status: "PASS",
        resource: apiArn,
        region,
        provider: "aws",
        details: `API "${apiName}" (${apiId}) has no resource methods defined.`,
        remediation: "No action required.",
      });
    }
  }

  return results;
}
