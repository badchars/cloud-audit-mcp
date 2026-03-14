# Cross-Cloud Attack Patterns

> Extracted from 3 HTB BlackSky assessments (HailStorm/AWS, Cyclone/Azure, Blizzard/GCP)

## 1. Credential Chain Attacks

The most common pattern across all 3 clouds: one credential leads to another.

### AWS Chain (HailStorm)
```
Public S3 → SSH key → EC2 shell → IMDS creds → EBS snapshot → root SSH key
→ Git history → IAM user creds → API Gateway LFI → Lambda env vars
→ Policy version escalation → ECR → Docker layer creds → Secrets Manager
→ Bash history creds → DynamoDB credential dump → Jenkins creds
→ PD4ML LFI → Lambda privesc → Admin → SageMaker
```

### Azure Chain (Cyclone)
```
AD login → Automation runbook creds → DSC plaintext password
→ WinRM access → lateral movement (password reuse) → PRT theft (Mimikatz)
→ Storage account access → ACR creds → Logic App SSRF → Key Vault
→ Cloud Shell token theft → error log credentials → SQL database
→ IMDS token → web app publishing creds → source code → SAS token
→ Function App code → Key Vault secrets → OAuth phishing → OneDrive
```

### GCP Chain (Blizzard)
```
Public GCS → source code → command injection → SSH shell
→ Metadata startup-script creds → SQL backup with passwords → root
→ K8s discovery → SQLite injection → webshell → K8s SA token
→ Cluster-admin → privileged DaemonSet → host escape → metadata token
→ GCR image pull → IAM delegation chain (5 hops) → SA key in bucket
→ App Engine source code → hardcoded creds → Token Creator abuse
→ setMetadata SSH key injection → root on any instance
```

---

## 2. Metadata Service Exploitation

All 3 clouds have metadata endpoints that expose credentials:

| Cloud | Endpoint | Token Required | Key Data |
|-------|----------|---------------|----------|
| AWS (IMDSv1) | `169.254.169.254/latest/meta-data/iam/security-credentials/ROLE` | No | Temp AccessKey/SecretKey/Token |
| AWS (IMDSv2) | Same, but requires PUT for token first | Yes (header) | Same |
| Azure IMDS | `169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/` | `Metadata: true` header | OAuth2 Bearer token |
| GCP Metadata | `169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` | `Metadata-Flavor: Google` header | OAuth2 access token |

### Universal Checks:
- **Startup scripts** containing secrets (all 3 clouds)
- **Instance scope/permissions** too broad (all 3 clouds)
- **Container escape to metadata** (AWS ECS/EKS, Azure ACI/AKS, GCP GKE)

---

## 3. Container/Image Credential Exposure

Docker images across all 3 registries (ECR, ACR, GCR) contain secrets:

| Location | Detection Method |
|----------|-----------------|
| ENV instructions in Dockerfile | `docker history --no-trunc IMAGE` |
| Files in filesystem | `docker run IMAGE cat /etc/passwd`, `find /` |
| Intermediate layer artifacts | `docker save IMAGE -o img.tar` → extract layers → search |
| Config/manifest metadata | Image inspect, manifest JSON |

### Checks:
1. Pull all images from registry
2. Run `docker history --no-trunc` → scan for credential patterns
3. Run `docker save` → extract all layers → grep for secrets
4. Run container → scan common secret paths (`/root/`, `/home/`, `/etc/`, `/var/`)

---

## 4. IAM Privilege Escalation Paths

### AWS Privilege Escalation Methods (from assessment):
| Method | Required Permissions | Impact |
|--------|---------------------|--------|
| Policy Version Switch | `iam:SetDefaultPolicyVersion` | Activate dormant elevated policy |
| Lambda Code Injection | `lambda:UpdateFunctionCode` | Steal env vars, execute as Lambda role |
| Lambda + PassRole | `lambda:CreateFunction` + `iam:PassRole` | Execute code as any passable role |
| Event Source Bypass | `lambda:CreateEventSourceMapping` + write to source | Indirect Lambda invocation |
| Direct Admin Attach | `iam:AttachUserPolicy` | Self-escalate to admin |

### Azure Privilege Escalation Methods:
| Method | Required Permissions | Impact |
|--------|---------------------|--------|
| PRT Theft | RDP + no Credential Guard | Impersonate any Azure AD user |
| Logic App SSRF | HTTP trigger + MSI | Read Key Vault, access any Azure resource |
| Managed Identity Abuse | VM with Contributor MI | List resources, extract credentials |
| Publishing Credential Theft | Website Contributor on MI | Access Kudu, read source code |
| OAuth Consent Phishing | App Registration + SMTP | Access victim's files/email |

### GCP Privilege Escalation Methods:
| Method | Required Permissions | Impact |
|--------|---------------------|--------|
| SA Key Creation | `iam.serviceAccountKeys.create` | Persistent access as target SA |
| Implicit Delegation | `iam.serviceAccounts.implicitDelegation` | Multi-hop SA impersonation |
| Token Generation | `iam.serviceAccounts.getAccessToken` | Direct SA impersonation |
| SSH Key Injection | `compute.instances.setMetadata` | Root SSH on any instance |
| Cluster-Admin Abuse | K8s cluster-admin RBAC | Full cluster control + host escape |

---

## 5. Storage Misconfiguration Patterns

| Cloud | Service | Misconfiguration | Severity |
|-------|---------|-----------------|----------|
| AWS | S3 | `Principal: "*"` in bucket policy | CRITICAL |
| AWS | S3 | `AllUsers` ACL grant | CRITICAL |
| AWS | S3 | Block Public Access disabled | CRITICAL |
| Azure | Blob Storage | `allowBlobPublicAccess: true` | CRITICAL |
| Azure | Blob Storage | Container access level `blob`/`container` | CRITICAL |
| Azure | Storage | Long-lived SAS tokens (>90 days) | HIGH |
| GCP | GCS | `allUsers` in IAM binding | CRITICAL |
| GCP | GCS | `allAuthenticatedUsers` in IAM binding | HIGH |

### What to Find in Exposed Storage:
1. **Private keys** — SSH, TLS, service account JSON
2. **Database backups** — SQL dumps with cleartext passwords
3. **Source code** — application code revealing vulnerabilities + hardcoded creds
4. **Configuration** — `.env`, connection strings, API keys
5. **Deployment packages** — ZIP/SquashFS with function/app code

---

## 6. Network Exposure Patterns

### Dangerous Exposed Ports (All Clouds):
| Port | Service | Risk | Cloud |
|------|---------|------|-------|
| 22 | SSH | Remote access | All |
| 25 | SMTP | Open relay (phishing) | Azure |
| 3389 | RDP | Remote access | Azure |
| 5985/5986 | WinRM | PowerShell remoting | Azure |
| 8080 | Jenkins/Admin | Unauthenticated admin | AWS |
| 10250 | Kubelet API | Container exec | GCP/All |
| 16443 | K8s API | Cluster control | GCP |
| 32156+ | NodePort | Internal app exposure | GCP/All |

---

## 7. Secret Storage Anti-Patterns

Secrets found in wrong places across all assessments:

| Anti-Pattern | Where Found | Cloud | Correct Alternative |
|-------------|-------------|-------|-------------------|
| Plaintext in startup scripts | GCE metadata | GCP | Secret Manager |
| Plaintext in DSC configs | Automation Account | Azure | Key Vault |
| Hardcoded in Dockerfile ENV | ECR image layers | AWS | BuildKit secrets |
| In `.bash_history` | EC2 instances | AWS | IAM roles, no export |
| In git commit history | EC2 filesystem | AWS | git-secrets, rotate |
| In DynamoDB table | DynamoDB | AWS | Secrets Manager |
| In AD group description | Azure AD | Azure | Key Vault |
| In runbook source code | Automation | Azure | Key Vault references |
| In Cloud Shell error logs | Cloud Shell .img | Azure | Secret Manager |
| In web app connection strings | App Service config | Azure | Managed Identity |
| In source code (SAS tokens) | Web App source | Azure | Short-lived tokens |
| In SQL database backup | GCS bucket | GCP | Encrypt backups |
| In PHP source code | GCS bucket | GCP | Secret Manager |
| In note.txt / projects.csv | EC2 filesystem | AWS | Secrets Manager |
| In Jenkins credential store | Jenkins UI | AWS | External vault |

---

## 8. Kubernetes Attack Surface (GCP Assessment)

### Attack Flow:
```
1. Find K8s nodes via internal network scan
2. Access NodePort services → web app vulnerabilities
3. Get pod SA token from /var/run/secrets/kubernetes.io/serviceaccount/token
4. Check RBAC: SelfSubjectRulesReview
5. If cluster-admin: create privileged DaemonSet with hostPath "/"
6. Use Kubelet API (:10250/run/) to exec into pods
7. Mount host filesystem → read /etc/shadow, SSH keys, flags
8. Query GCE metadata from host → steal SA token
9. Use SA token for cloud API access (GCR, GCS, IAM)
```

### K8s Security Checklist:
- [ ] No `cluster-admin` on default service accounts
- [ ] Pod Security Standards enforced (Restricted)
- [ ] `automountServiceAccountToken: false` on unused SAs
- [ ] No privileged containers allowed
- [ ] No hostPath volume mounts allowed
- [ ] Kubelet API authentication required
- [ ] NetworkPolicies restricting pod-to-pod traffic
- [ ] Metadata concealment enabled (GKE)
- [ ] Workload Identity enabled (GKE)
