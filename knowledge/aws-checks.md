# AWS Security Checks Knowledge Base

> Source: HTB BlackSky HailStorm Assessment (23 vulnerabilities, full AWS attack chain)

## Check Categories

### 1. S3 Bucket Security

#### S3-001: Public Bucket Access
- **Severity:** CRITICAL
- **Description:** S3 bucket configured with public read access (ACL or policy allows `*` or unauthenticated access)
- **API Calls:**
  - `s3api:GetBucketPolicy` — check for `"Principal": "*"` or `"Principal": {"AWS": "*"}`
  - `s3api:GetBucketAcl` — check for `AllUsers` or `AuthenticatedUsers` grants
  - `s3api:GetPublicAccessBlock` — verify all 4 settings are `true`
  - `s3:ListBuckets` — enumerate all buckets
- **Detection Logic:**
  ```
  IF bucket_policy.Principal == "*" OR
     bucket_acl contains "AllUsers" OR
     public_access_block has any false setting
  THEN CRITICAL
  ```
- **Remediation:**
  ```bash
  aws s3api put-public-access-block --bucket BUCKET \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  ```

#### S3-002: Sensitive Objects in Buckets
- **Severity:** CRITICAL
- **Description:** SSH keys, credentials, database backups, or source code stored in S3
- **API Calls:**
  - `s3:ListObjectsV2` — enumerate objects
- **Detection Patterns:**
  - `id_rsa`, `*.pem`, `*.key` — SSH/TLS private keys
  - `*.sql`, `*.dump`, `*.bak` — database backups with cleartext passwords
  - `*.env`, `credentials`, `config.json` — configuration with secrets
  - `*.js`, `*.py`, `*.php`, `*.go` — application source code
- **Real Attack:** Public bucket contained SSH private key for `webadmin` user + Node.js source code revealing command injection

#### S3-003: Bucket Name Leaks AWS Account ID
- **Severity:** LOW
- **Description:** Bucket name contains AWS account ID (e.g., `logistics-assets-940428791287`)
- **Detection:** Regex match `\d{12}` in bucket name
- **Remediation:** Use random/opaque bucket names, serve via CloudFront

---

### 2. IAM Security

#### IAM-001: Policy Version Privilege Escalation
- **Severity:** CRITICAL
- **Description:** Non-default IAM policy versions contain elevated permissions that can be activated via `iam:SetDefaultPolicyVersion`
- **API Calls:**
  - `iam:ListPolicyVersions` — enumerate all versions
  - `iam:GetPolicyVersion` — compare permissions across versions
- **Detection Logic:**
  ```
  FOR each policy:
    IF version_count > 1:
      Compare default vs non-default versions
      IF non_default has more permissions THEN HIGH
      IF any version grants iam:SetDefaultPolicyVersion THEN CRITICAL
  ```
- **Real Attack:** `AWSLambdaBasicExecutionRole` v1 had `iam:SetDefaultPolicyVersion`, v2 had ECR permissions. Attacker activated v2 to gain ECR access.
- **Remediation:** Delete unused policy versions. Never grant `iam:SetDefaultPolicyVersion`.

#### IAM-002: Dangerous Permission Combinations
- **Severity:** CRITICAL
- **Description:** IAM entities with privilege escalation paths
- **Dangerous Combos:**
  | Combo | Escalation Path |
  |-------|----------------|
  | `iam:PassRole` + `lambda:CreateFunction` | Create Lambda with high-priv role |
  | `lambda:UpdateFunctionCode` | Inject code into existing Lambda, steal env vars |
  | `lambda:CreateEventSourceMapping` + `dynamodb:PutItem` | Indirect Lambda invocation bypass |
  | `iam:SetDefaultPolicyVersion` | Activate dormant elevated policy |
  | `iam:AttachUserPolicy` / `iam:AttachRolePolicy` | Self-escalate to admin |
  | `iam:CreateUser` + `iam:CreateAccessKey` | Create backdoor admin user |
  | `iam:PutUserPolicy` / `iam:PutRolePolicy` | Inline policy escalation |
- **Real Attack:** `amelia` had `lambda:CreateFunction` + `iam:PassRole` for `data_mgr` role (which had `AdministratorAccess`). Created Lambda that attached admin policy to herself.
- **API Calls:**
  - `iam:GetPolicy`, `iam:GetPolicyVersion` for all attached policies
  - `iam:ListAttachedUserPolicies`, `iam:ListAttachedRolePolicies`
  - `iam:ListUserPolicies`, `iam:ListRolePolicies` (inline)

#### IAM-003: Lambda Execution Roles with Admin Access
- **Severity:** CRITICAL
- **Description:** Lambda execution roles with `AdministratorAccess` or overly broad policies
- **API Calls:**
  - `lambda:ListFunctions` → `Role` field
  - `iam:ListAttachedRolePolicies` for each execution role
- **Real Attack:** `data_mgr` role had `AdministratorAccess`, was passable to new Lambda functions

#### IAM-004: Git Repository Credential Exposure
- **Severity:** CRITICAL
- **Description:** AWS credentials committed to Git history (even if "removed" in later commits)
- **Detection:** Scan `.git/` directories for patterns: `AKIA*`, `AWS_SECRET_ACCESS_KEY`, `aws_access_key_id`
- **Real Attack:** `git show d9d1b0b` in `/opt/deployment/` revealed `daniel`'s AWS credentials

---

### 3. EC2 / IMDS Security

#### EC2-001: IMDSv1 Enabled
- **Severity:** HIGH
- **Description:** Instance Metadata Service v1 allows unauthenticated token-less access to IAM credentials
- **API Calls:**
  - `ec2:DescribeInstances` → check `MetadataOptions.HttpTokens`
- **Detection:**
  ```
  IF HttpTokens == "optional" THEN HIGH  (IMDSv1 enabled)
  IF HttpTokens == "required" THEN OK    (IMDSv2 only)
  ```
- **Remediation:**
  ```bash
  aws ec2 modify-instance-metadata-options --instance-id i-xxx \
    --http-tokens required --http-put-response-hop-limit 1
  ```
- **Real Attack:** `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/web01` yielded full IAM credentials

#### EC2-002: EBS Snapshots Unencrypted/Accessible
- **Severity:** CRITICAL
- **Description:** Unencrypted EBS snapshots accessible to roles with volume management permissions
- **API Calls:**
  - `ec2:DescribeSnapshots` — check encryption status + permissions
  - `ec2:DescribeVolumes` — check encryption
- **Detection:**
  ```
  IF snapshot.Encrypted == false THEN HIGH
  IF snapshot shared publicly THEN CRITICAL
  IF role has ec2:CreateVolume + ec2:AttachVolume for any snapshot THEN HIGH
  ```
- **Real Attack:** Unencrypted snapshot contained root SSH key at `/root/.ssh/id_rsa`
- **Remediation:** Encrypt all snapshots. Use `aws ec2 enable-ebs-encryption-by-default`.

#### EC2-003: Security Groups with 0.0.0.0/0
- **Severity:** HIGH
- **Description:** Security groups allowing inbound traffic from any IP on sensitive ports
- **API Calls:** `ec2:DescribeSecurityGroups`
- **Sensitive Ports:** 22 (SSH), 3389 (RDP), 8080 (Jenkins/admin), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB), 9200 (Elasticsearch)
- **Real Attack:** Jenkins on port 8080 accessible with public user registration enabled

---

### 4. Lambda Security

#### LAMBDA-001: Secrets in Environment Variables
- **Severity:** CRITICAL
- **Description:** Lambda functions storing credentials, API keys, or tokens in environment variables
- **API Calls:**
  - `lambda:ListFunctions`
  - `lambda:GetFunctionConfiguration` → `Environment.Variables`
- **Detection Patterns:** `AWS_`, `KEY`, `SECRET`, `PASSWORD`, `TOKEN`, `API_KEY`, `DATABASE_URL`, `CONNECTION_STRING`
- **Real Attack:** LFI via `file:///proc/self/environ` on Lambda exposed all env vars including temp AWS credentials

#### LAMBDA-002: UpdateFunctionCode Permission
- **Severity:** CRITICAL
- **Description:** Roles with `lambda:UpdateFunctionCode` can inject malicious code + steal env vars
- **Real Attack:** `app03` role had `lambda:UpdateFunctionCode` — deployed code that extracted all environment variables (including flags and credentials)
- **Remediation:** Restrict to CI/CD roles only. Don't store secrets in Lambda env vars (use Secrets Manager).

#### LAMBDA-003: Event Source Mapping as Invocation Bypass
- **Severity:** HIGH
- **Description:** `lambda:CreateEventSourceMapping` + write access to event source = indirect Lambda invocation
- **Real Attack:** `amelia` lacked `lambda:InvokeFunction` but had `lambda:CreateEventSourceMapping` + `dynamodb:PutItem`. Created mapping to DynamoDB stream, wrote item to trigger Lambda.

---

### 5. ECR / Container Security

#### ECR-001: Hardcoded Credentials in Docker Images
- **Severity:** CRITICAL
- **Description:** AWS credentials or secrets embedded in Dockerfile ENV instructions persist in image layer metadata
- **Detection:**
  - `docker history --no-trunc IMAGE` — check for ENV with credential patterns
  - `docker save IMAGE -o image.tar` → extract layers → search for secrets
- **API Calls:**
  - `ecr:DescribeRepositories`
  - `ecr:DescribeImages`
  - `ecr:BatchGetImage` → manifest → layer digests
- **Real Attack:** `docker history` revealed `sara`'s AWS credentials hardcoded as ENV in Dockerfile

#### ECR-002: Sensitive Files in Image Layers
- **Severity:** MEDIUM
- **Description:** Intermediate Docker layers contain sensitive files not cleaned by multi-stage builds
- **Real Attack:** TAR extraction of blob layers revealed flag files that were added then "removed"

---

### 6. Secrets Manager

#### SM-001: Over-Permissive Secret Access
- **Severity:** HIGH
- **Description:** Secrets accessible by overly broad IAM principals without resource-based policies
- **API Calls:**
  - `secretsmanager:ListSecrets`
  - `secretsmanager:GetResourcePolicy` — verify resource-based policies exist
- **Real Attack:** `sara`'s credentials accessed `File_Server_Access` secret containing SSH credentials
- **Remediation:** Implement resource-based policies on every secret. Restrict `secretsmanager:GetSecretValue` to specific roles.

---

### 7. DynamoDB Security

#### DYNAMO-001: Cleartext Credentials in Tables
- **Severity:** CRITICAL
- **Description:** DynamoDB tables storing AWS IAM keys and passwords without application-level encryption
- **API Calls:**
  - `dynamodb:ListTables`
  - `dynamodb:DescribeTable` — check encryption + table name patterns
- **Detection:** Flag tables named `Users`, `Credentials`, `Keys`, `Secrets`, `Config`
- **Real Attack:** `dynamodb:scan` on credentials table revealed cleartext AWS keys and SSH passwords for multiple users

#### DYNAMO-002: DynamoDB Streams to Lambda Chains
- **Severity:** HIGH
- **Description:** DynamoDB Streams connected to Lambda functions with elevated execution roles
- **API Calls:**
  - `dynamodb:DescribeTable` — check `StreamSpecification`
  - `lambda:ListEventSourceMappings` — check connected functions
  - Cross-check Lambda execution role permissions

---

### 8. API Gateway

#### APIGW-001: API Without Authentication
- **Severity:** HIGH
- **Description:** REST APIs without proper authentication allowing direct access to backend Lambda functions
- **API Calls:**
  - `apigateway:GetRestApis`
  - `apigateway:GetResources`
  - `apigateway:GetMethod` — check `authorizationType`
- **Real Attack:** `Freight-Tracking` API allowed unauthenticated access, backend Lambda had LFI vulnerability

---

### 9. SageMaker

#### SAGE-001: Notebook Instance Access
- **Severity:** HIGH
- **Description:** Roles with `sagemaker:CreatePresignedNotebookInstanceUrl` can access JupyterLab terminals
- **API Calls:**
  - `sagemaker:ListNotebookInstances`
  - Check IAM policies for `sagemaker:CreatePresigned*`
- **Real Attack:** Admin user generated presigned URL to access `project-notes` notebook terminal
- **Remediation:** Restrict notebook access. Implement VPC-only access. Use IAM conditions.

---

### 10. Cross-Cutting Patterns

#### PATTERN-001: Credential Chain Detection
AWS credentials found in one location lead to access in another:
- S3 bucket → SSH key → EC2 access → IMDS → more AWS creds
- Git history → IAM user creds → API Gateway → Lambda env vars → more creds
- ECR image layers → IAM user creds → Secrets Manager → SSH creds
- DynamoDB table → multiple user creds → lateral movement
- Jenkins credential store → SSH keys + passwords → more hosts

#### PATTERN-002: Bash History Credential Exposure
- **Severity:** HIGH
- **Description:** AWS credentials exported in shell sessions persist in `.bash_history`
- **Real Attack:** `cat .bash_history` revealed root password and AWS credentials for IAM user `lucifer`

#### PATTERN-003: Plaintext Credentials in Files
- Check for: `note.txt`, `credentials.txt`, `config.json`, `projects.csv` containing passwords
- **Real Attack:** `/root/projects.csv` on Jenkins server contained AWS credentials + plaintext passwords

---

## AWS CLI Commands Reference

```bash
# Identity
aws sts get-caller-identity

# S3
aws s3api get-bucket-policy --bucket BUCKET
aws s3api get-bucket-acl --bucket BUCKET
aws s3api get-public-access-block --bucket BUCKET
aws s3api list-objects-v2 --bucket BUCKET

# IAM
aws iam list-policy-versions --policy-arn ARN
aws iam get-policy-version --policy-arn ARN --version-id v1
aws iam list-attached-role-policies --role-name ROLE
aws iam list-attached-user-policies --user-name USER

# EC2
aws ec2 describe-instances --query 'Reservations[].Instances[].{Id:InstanceId,IMDS:MetadataOptions}'
aws ec2 describe-snapshots --owner-ids self
aws ec2 describe-security-groups

# Lambda
aws lambda list-functions
aws lambda get-function-configuration --function-name FUNC

# ECR
aws ecr describe-repositories
aws ecr describe-images --repository-name REPO

# DynamoDB
aws dynamodb list-tables
aws dynamodb describe-table --table-name TABLE

# Secrets Manager
aws secretsmanager list-secrets

# SageMaker
aws sagemaker list-notebook-instances

# API Gateway
aws apigateway get-rest-apis
```
