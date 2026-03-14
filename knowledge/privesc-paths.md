# IAM Privilege Escalation Paths

> Sources: Rhino Security Labs, Pacu Framework, MITRE ATT&CK, HTB Assessments

## AWS IAM Privilege Escalation (21+ Methods)

### Category 1: Direct Policy Manipulation

| # | Method | Required Permission | Impact |
|---|--------|-------------------|--------|
| 1 | Create policy version | `iam:CreatePolicyVersion` | Create new admin policy version |
| 2 | Set default policy version | `iam:SetDefaultPolicyVersion` | Activate dormant elevated version |
| 3 | Attach user policy | `iam:AttachUserPolicy` | Attach AdministratorAccess |
| 4 | Attach group policy | `iam:AttachGroupPolicy` | Attach admin to own group |
| 5 | Attach role policy | `iam:AttachRolePolicy` | Elevate any role |
| 6 | Put user inline policy | `iam:PutUserPolicy` | Create admin inline policy |
| 7 | Put group inline policy | `iam:PutGroupPolicy` | Admin inline on own group |
| 8 | Put role inline policy | `iam:PutRolePolicy` | Admin inline on any role |
| 9 | Add user to group | `iam:AddUserToGroup` | Join admin group |

### Category 2: Credential Theft

| # | Method | Required Permission | Impact |
|---|--------|-------------------|--------|
| 10 | Create access key | `iam:CreateAccessKey` | Generate keys for other users |
| 11 | Create login profile | `iam:CreateLoginProfile` | Set console password for another user |
| 12 | Update login profile | `iam:UpdateLoginProfile` | Change another user's password |
| 13 | Update AssumeRolePolicy | `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` | Modify trust policy to assume any role |

### Category 3: Service Abuse (PassRole Chains)

| # | Method | Required Permissions | Impact |
|---|--------|---------------------|--------|
| 14 | EC2 instance with role | `iam:PassRole` + `ec2:RunInstances` | Launch instance, steal role creds via IMDS |
| 15 | Lambda + invoke | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Execute code as privileged role |
| 16 | Lambda + trigger | `iam:PassRole` + `lambda:CreateFunction` + `lambda:CreateEventSourceMapping` | Trigger via DynamoDB/S3/SQS stream |
| 17 | Update Lambda code | `lambda:UpdateFunctionCode` | Modify existing function to exfil creds |
| 18 | CloudFormation stack | `iam:PassRole` + `cloudformation:CreateStack` | Stack executes with passed role |
| 19 | Glue dev endpoint | `iam:PassRole` + `glue:CreateDevEndpoint` | SSH into endpoint, get role creds |
| 20 | Data Pipeline | `iam:PassRole` + `datapipeline:CreatePipeline` | Pipeline runs with role permissions |
| 21 | SageMaker notebook | `iam:PassRole` + `sagemaker:CreateNotebookInstance` | Notebook gets role credentials |

### Detection API Calls
```bash
# Check if any policy grants escalation permissions
aws iam list-policies --scope Local --query 'Policies[*].Arn'
# For each policy, check all versions
aws iam list-policy-versions --policy-arn ARN
aws iam get-policy-version --policy-arn ARN --version-id vN
# Check for dangerous actions
# Pattern: iam:Create*, iam:Attach*, iam:Put*, iam:Update*, iam:PassRole, lambda:Create*, lambda:Update*
```

---

## GCP IAM Privilege Escalation (17 Methods)

| # | Method | Required Permission | Impact |
|---|--------|-------------------|--------|
| 1 | SA impersonation | `iam.serviceAccounts.getAccessToken` | Get access token for any SA |
| 2 | SA key creation | `iam.serviceAccountKeys.create` | Export persistent credentials |
| 3 | Implicit delegation | `iam.serviceAccounts.implicitDelegation` | Chain SA impersonation (multi-hop) |
| 4 | Sign blob | `iam.serviceAccounts.signBlob` | Forge credentials |
| 5 | Sign JWT | `iam.serviceAccounts.signJwt` | Forge JWT tokens |
| 6 | Cloud Function create | `cloudfunctions.functions.create` + `iam.serviceAccounts.actAs` | Execute code as SA |
| 7 | Cloud Function update | `cloudfunctions.functions.update` | Modify existing function |
| 8 | Compute instance create | `compute.instances.create` + `iam.serviceAccounts.actAs` | VM with SA, metadata server |
| 9 | Cloud Build create | `cloudbuild.builds.create` | Build runs with elevated SA |
| 10 | Cloud Run create | `run.services.create` + `iam.serviceAccounts.actAs` | Service runs as SA |
| 11 | Cloud Scheduler | `cloudscheduler.jobs.create` + `iam.serviceAccounts.actAs` | Scheduled tasks as SA |
| 12 | Deployment Manager | `deploymentmanager.deployments.create` | Deploy infra as SA |
| 13 | Role update | `iam.roles.update` | Modify custom role permissions |
| 14 | Org policy set | `orgpolicy.policy.set` | Bypass org-level security controls |
| 15 | HMAC key create | `storage.hmacKeys.create` | Storage access via HMAC |
| 16 | API key create | `serviceusage.apiKeys.create` | Generate API keys |
| 17 | setMetadata SSH injection | `compute.instances.setMetadata` | Root SSH on any instance |

### Detection: Build Permission Graph
```
1. List all SAs: iam.serviceAccounts.list
2. For each SA, get IAM policy: getIamPolicy
3. Test dangerous permissions: testIamPermissions
4. Build directed graph: SA_A → SA_B if A has actAs/getAccessToken/implicitDelegation/keyCreate on B
5. Find all transitive paths > 1 hop
6. Flag paths reaching high-privilege SAs
```

---

## Azure Privilege Escalation Methods

| # | Method | Required Condition | Impact |
|---|--------|-------------------|--------|
| 1 | PRT Theft | RDP + no Credential Guard | Impersonate any Azure AD user |
| 2 | Logic App SSRF | HTTP trigger + MSI + Key Vault access | Read any Key Vault secret |
| 3 | Managed Identity Abuse | VM with Contributor/Owner MI | Full subscription access |
| 4 | Publishing Cred Theft | Website Contributor on MI | Kudu access, source code read |
| 5 | OAuth Consent Phishing | App Registration + user consent enabled | Access victim's files/email |
| 6 | Automation Cred Theft | Reader on Automation Account | Read runbook/DSC plaintext creds |
| 7 | Cloud Shell Token Theft | Access to VM with cached .azure/ tokens | Impersonate cached users |
| 8 | SQL Connection String Theft | Access to web app config | Database access with embedded creds |
| 9 | SAS Token from Source | Read access to web app source | Storage access via hardcoded SAS |
| 10 | Function App Key Vault | Anonymous function + MSI | Read all Key Vault secrets |

---

## Cross-Account / Federation Risks

### Confused Deputy Problem (AWS)
- **Issue:** 37% of third-party vendors do not implement `ExternalId` correctly in IAM trust policies
- **Risk:** Any AWS account can assume the vendor's cross-account role
- **Check:** `aws iam get-role --role-name ROLE` → verify `Condition` has `sts:ExternalId`
- **Pattern:** Trust policy with `"Principal": {"AWS": "arn:aws:iam::VENDOR_ACCOUNT:root"}` without ExternalId condition

### Golden SAML Attack
- **Issue:** Stolen ADFS/IdP token-signing certificates allow forging SAML assertions for any user
- **Impact:** Bypass MFA entirely, produces zero events at the IdP
- **Real-World:** Used in SolarWinds/NOBELIUM attack
- **Check:** Monitor SAML token-signing cert rotation, detect unusual SAML assertions

### OAuth Token Chain (Azure)
- **Issue:** Azure CLI caches refresh tokens on disk (`accessTokens.json`) without encryption
- **Risk:** Token theft → refresh → impersonate any cached user → access their resources
- **Check:** Detect VMs with cached Azure CLI tokens, check disk encryption

---

## Privilege Escalation Detection Checklist

### For Each IAM Entity (User/Role/SA), Check:

```
AWS:
  [ ] Can create/attach/put policies? → Direct admin escalation
  [ ] Can PassRole to high-priv roles? → Service abuse escalation
  [ ] Can CreateAccessKey for other users? → Credential theft
  [ ] Can UpdateAssumeRolePolicy? → Trust policy hijack
  [ ] Can SetDefaultPolicyVersion? → Dormant policy activation
  [ ] Can UpdateFunctionCode? → Lambda code injection
  [ ] Can CreateEventSourceMapping? → Indirect invocation

GCP:
  [ ] Can getAccessToken for other SAs? → Direct impersonation
  [ ] Can createKey for other SAs? → Persistent credential theft
  [ ] Has implicitDelegation? → Multi-hop chain
  [ ] Can signBlob/signJwt? → Credential forgery
  [ ] Can create compute/functions with actAs? → Service abuse
  [ ] Can setMetadata? → SSH key injection
  [ ] Can update iam.roles? → Custom role escalation

Azure:
  [ ] Has Contributor/Owner on subscription? → Full admin
  [ ] MI with Website Contributor? → Source code access
  [ ] MI with Key Vault access + HTTP endpoint? → SSRF to secrets
  [ ] Can modify Automation runbooks? → Credential injection
  [ ] Can register apps + user consent enabled? → OAuth phishing
  [ ] VM without Credential Guard? → PRT theft
```
