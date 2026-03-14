import type { CloudProvider, CheckResult, ToolContext } from "../types/index.js";

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

export async function runAll(
  provider: CloudProvider,
  ctx: ToolContext,
  args: { region?: string }
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const filterArgs = { region: args.region };

  if (provider === "aws") {
    const aws = ctx.getAwsClient();
    const checks = [
      () => checkS3Public(aws, filterArgs),
      () => checkS3Objects(aws, filterArgs),
      () => checkIamPolicies(aws, filterArgs),
      () => checkEc2Imds(aws, filterArgs),
      () => checkEc2Snapshots(aws, filterArgs),
      () => checkEc2SecurityGroups(aws, filterArgs),
      () => checkLambdaEnv(aws, filterArgs),
      () => checkLambdaPermissions(aws, filterArgs),
      () => checkEcrImages(aws, filterArgs),
      () => checkSecretsManager(aws, filterArgs),
      () => checkDynamodb(aws, filterArgs),
      () => checkApiGateway(aws, filterArgs),
      () => checkSageMaker(aws, filterArgs),
    ];

    for (const check of checks) {
      try {
        const r = await check();
        results.push(...r);
      } catch (err) {
        console.error(`[cloud-audit] AWS check error: ${(err as Error).message}`);
      }
    }
  }

  if (provider === "azure") {
    const azure = ctx.getAzureClient();
    const checks = [
      () => checkStoragePublic(azure, {}),
      () => checkStorageSas(azure, {}),
      () => checkAutomation(azure, {}),
      () => checkVmNetwork(azure, {}),
      () => checkVmEncryption(azure, {}),
      () => checkVmIdentity(azure, {}),
      () => checkAdConsent(azure, {}),
      () => checkLogicApps(azure, {}),
      () => checkFunctions(azure, {}),
      () => checkKeyvault(azure, {}),
      () => checkAcr(azure, {}),
      () => checkSql(azure, {}),
      () => checkWebapp(azure, {}),
    ];

    for (const check of checks) {
      try {
        const r = await check();
        results.push(...r);
      } catch (err) {
        console.error(`[cloud-audit] Azure check error: ${(err as Error).message}`);
      }
    }
  }

  if (provider === "gcp") {
    const gcp = ctx.getGcpClient();
    const checks = [
      () => checkGcsPublic(gcp, {}),
      () => checkGcsObjects(gcp, {}),
      () => checkMetadata(gcp, {}),
      () => checkIamKeys(gcp, {}),
      () => checkIamDelegation(gcp, {}),
      () => checkIamCompute(gcp, {}),
      () => checkKubernetes(gcp, {}),
      () => checkGcr(gcp, {}),
    ];

    for (const check of checks) {
      try {
        const r = await check();
        results.push(...r);
      } catch (err) {
        console.error(`[cloud-audit] GCP check error: ${(err as Error).message}`);
      }
    }
  }

  ctx.addFindings(results);
  return results;
}
