# Azure Security Checks Knowledge Base

> Source: HTB BlackSky Cyclone Assessment (15 vulnerabilities, full Azure attack chain)

## Check Categories

### 1. Azure AD / Entra ID Security

#### AAD-001: Secrets in AD Object Descriptions
- **Severity:** MEDIUM
- **Description:** Azure AD groups, users, or applications with secrets/passwords in description fields
- **API Calls:**
  - `GET /v1.0/groups?$select=displayName,description` (Graph API)
  - `GET /v1.0/users?$select=displayName,description`
- **Real Attack:** Flag embedded in group description, discoverable by any authenticated user
- **Remediation:** Audit all AD object descriptions. Use Key Vault for secrets.

#### AAD-002: User Consent Settings (OAuth Phishing)
- **Severity:** CRITICAL
- **Description:** Users allowed to consent to third-party apps requesting dangerous permissions
- **API Calls:**
  - `GET /v1.0/policies/authorizationPolicy` → check `permissionGrantPolicyIdsAssignedToDefaultUserRole`
- **Dangerous Scopes:** `Files.ReadWrite.All`, `Mail.Read`, `Mail.Send`, `Directory.ReadWrite.All`
- **Real Attack:** Attacker registered malicious app with `Files.ReadWrite.All` + `Mail.Read`, sent phishing email via internal SMTP relay, victim consented, attacker accessed OneDrive
- **Remediation:**
  ```bash
  # Require admin consent for all app registrations
  az ad sp update --id <enterprise-app-id> --set appRoleAssignmentRequired=true
  ```

#### AAD-003: PRT (Primary Refresh Token) Theft
- **Severity:** CRITICAL
- **Description:** Azure AD-joined machines without Credential Guard allow PRT extraction via Mimikatz
- **Attack Steps:**
  1. `mimikatz "sekurlsa::cloudap"` → extract PRT + KeyValue
  2. `mimikatz "dpapi::cloudapkd /keyvalue:..."` → decrypt session key
  3. `roadtx prt --prt <PRT> -s <SESSION_KEY> -a renew` → get access token
- **Detection:**
  - Check if Credential Guard is enabled on Azure AD-joined VMs
  - Check if LSASS protection (RunAsPPL) is enabled
- **Remediation:** Enable Credential Guard. Enable LSASS protection. Use Conditional Access with device compliance.

---

### 2. Azure Automation

#### AUTO-001: Hardcoded Credentials in Runbooks
- **Severity:** CRITICAL
- **Description:** Automation runbook source code containing hardcoded passwords, API keys, or secrets
- **API Calls:**
  ```
  GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Automation/automationAccounts/{account}/runbooks/{runbook}/content?api-version=2023-11-01
  ```
- **Detection:** Scan runbook content for credential patterns (passwords, connection strings, API keys)
- **Real Attack:** Runbook contained flag in comments and used `Get-AutomationPSCredential` with hardcoded credentials
- **Remediation:** Never store secrets in runbook code. Use Automation Credentials + Key Vault references.

#### AUTO-002: DSC Configuration Plaintext Passwords
- **Severity:** CRITICAL
- **Description:** DSC configurations with `SafemodeAdministratorPassword` or other credentials in plaintext
- **API Calls:**
  ```
  GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Automation/automationAccounts/{account}/configurations/{config}/content?api-version=2023-11-01
  ```
- **Detection Patterns:** `SafemodeAdministratorPassword`, `Credential`, `Password`, `PSCredential`
- **Real Attack:** DSC config contained `dsc` user credentials (`GNtrRHgfefbFE123!@#!`) enabling WinRM access to VMs
- **Remediation:**
  - Use `PSDscAllowPlainTextPassword = $false`
  - Store DSC credentials in Key Vault
  - Encrypt DSC MOF files

#### AUTO-003: Automation Variables Unencrypted
- **Severity:** HIGH
- **Description:** Automation Account variables storing sensitive data without encryption
- **API Calls:**
  ```
  GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Automation/automationAccounts/{account}/variables?api-version=2023-11-01
  ```
- **Detection:** Check `isEncrypted` field on each variable
- **Remediation:** Enable encryption for all sensitive variables.

---

### 3. Azure Storage

#### STOR-001: Public Blob Access Enabled
- **Severity:** CRITICAL
- **Description:** Storage account allows public anonymous access to containers/blobs
- **API Calls:**
  ```
  GET /subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01
  ```
- **Detection:** Check `properties.allowBlobPublicAccess == true`
- **Real Attack:** Public container with anonymous access contained encrypted Excel file
- **Remediation:**
  ```bash
  az storage account update --name ACCOUNT --allow-blob-public-access false
  ```

#### STOR-002: Container Public Access Level
- **Severity:** CRITICAL
- **Description:** Individual containers configured with `blob` or `container` access level
- **API Calls:**
  ```
  GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{account}/blobServices/default/containers?api-version=2021-09-01
  ```
- **Detection:** Check `properties.publicAccess` != `"None"`

#### STOR-003: Long-Lived SAS Tokens
- **Severity:** HIGH
- **Description:** SAS tokens with expiry > 90 days found in source code or configuration
- **Real Attack:** SAS token with expiry in 2030 found in web app source code
- **Detection:** Scan source code, app settings, and configuration for SAS token patterns (`sv=`, `sig=`, `se=`)
- **Remediation:** Set max SAS expiry policy. Use managed identities instead of SAS tokens.

#### STOR-004: Cloud Shell Storage Exposure
- **Severity:** HIGH
- **Description:** Cloud Shell storage accounts contain cached Azure CLI tokens and command history
- **API Calls:** List storage accounts with names starting with `cs` or `csb`
- **Real Attack:** Cloud Shell `.img` file contained cached tokens, error logs with plaintext credentials from `Invoke-AzVMRunCommand`
- **Remediation:** Regularly clean Cloud Shell storage. Use encrypted storage. Monitor Cloud Shell access.

---

### 4. Azure VMs / Network

#### VM-001: Management Ports Exposed to Internet
- **Severity:** CRITICAL
- **Description:** NSG rules allowing 0.0.0.0/0 to sensitive management ports
- **API Calls:**
  ```
  GET /subscriptions/{sub}/providers/Microsoft.Network/networkSecurityGroups?api-version=2021-02-01
  ```
- **Critical Ports:**
  | Port | Service | Risk |
  |------|---------|------|
  | 22 | SSH | Remote access |
  | 3389 | RDP | Remote access |
  | 5985/5986 | WinRM | PowerShell remoting |
  | 25 | SMTP | Open relay |
  | 8080 | Admin panels | Unauthenticated access |
- **Real Attack:** WinRM (5985) exposed to internet, accessed with DSC credentials via NTLM auth
- **Remediation:** Use Azure Bastion. Use Just-in-Time VM Access. Remove 0.0.0.0/0 rules.

#### VM-002: Unencrypted VM Disks
- **Severity:** HIGH
- **Description:** VM OS/data disks without Azure Disk Encryption
- **API Calls:**
  ```
  GET /subscriptions/{sub}/providers/Microsoft.Compute/disks?api-version=2021-04-01
  ```
- **Detection:** Check `properties.encryptionSettings.enabled`
- **Real Attack:** Unencrypted disk allowed token theft (Azure CLI token cache readable)
- **Remediation:** Enable Azure Disk Encryption on all VMs.

#### VM-003: Password Reuse Across VMs
- **Severity:** HIGH
- **Description:** Same credentials used on multiple VMs enabling lateral movement
- **Real Attack:** `dsc` credentials worked on 2 different VMs (Win10 + internal server)
- **Detection:** Cross-reference credentials found in DSC configs, Automation, Key Vault
- **Remediation:** Use LAPS (Local Admin Password Solution). Unique passwords per VM.

#### VM-004: Over-Privileged Managed Identities
- **Severity:** CRITICAL
- **Description:** VM managed identities with Contributor, Owner, or excessive RBAC roles
- **API Calls:**
  ```
  GET /subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01
  ```
- **Real Attack:** Linux VM's managed identity had "Website Contributor" role — used to extract web app publishing credentials and source code
- **Remediation:** Apply least-privilege RBAC. Use custom roles with minimal permissions.

#### VM-005: Azure IMDS Token Theft
- **Severity:** HIGH
- **Description:** Managed Identity tokens accessible from IMDS without restrictions
- **Attack Vector:**
  ```bash
  curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
  ```
- **Real Attack:** VM IMDS token used to enumerate web apps, extract publishing credentials, read source code

---

### 5. Azure Logic Apps

#### LOGIC-001: SSRF via Managed Identity
- **Severity:** CRITICAL
- **Description:** Logic App accepts user-controlled URL parameter and makes authenticated requests using its Managed Identity
- **API Calls:**
  - Get workflow definition: `GET .../workflows/{name}?api-version=2016-06-01`
  - List callback URLs: `POST .../triggers/manual/listCallbackUrl?api-version=2016-06-01`
- **Detection:**
  1. Check HTTP trigger actions for user-controlled URL parameters
  2. Check if Logic App has Managed Identity with Key Vault or storage access
  3. Look for patterns: `@triggerBody()?['url']` passed to HTTP action
- **Real Attack:** Logic App's MSI had Key Vault access. User-controlled `url` parameter directed MSI to read Key Vault secrets.
- **Remediation:**
  - Validate/allowlist URLs in Logic App
  - Never pass user input to HTTP actions
  - Use separate managed identities with least-privilege

---

### 6. Azure Functions

#### FUNC-001: Anonymous Auth Level
- **Severity:** CRITICAL
- **Description:** Azure Functions with `authLevel: "anonymous"` on sensitive endpoints
- **Detection:** Check `function.json` for `authLevel` setting
- **Real Attack:** Function with anonymous auth + user-controlled `vault` parameter → direct Key Vault secret access
- **Remediation:** Use `authLevel: "function"` or `"admin"`. Implement input validation.

#### FUNC-002: User Input Passed to Key Vault
- **Severity:** CRITICAL
- **Description:** Function directly passes user-controlled parameter as Key Vault secret name
- **Real Attack:** `GET /api/keyvault?vault=flag` → `SecretClient.get_secret(user_input)`
- **Remediation:** Validate/allowlist secret names. Don't expose Key Vault read operations via public endpoints.

---

### 7. Azure Key Vault

#### KV-001: Overly Permissive Access Policies
- **Severity:** HIGH
- **Description:** Key Vault with broad `Get` + `List` permissions on secrets
- **API Calls:**
  ```
  GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}?api-version=2021-06-01-preview
  ```
- **Detection:** Check `properties.accessPolicies` for overly broad permissions
- **Remediation:** Apply least-privilege access policies. Use RBAC instead of access policies.

#### KV-002: Network Access Not Restricted
- **Severity:** MEDIUM
- **Description:** Key Vault with `defaultAction: "Allow"` instead of `"Deny"`
- **Detection:** Check `properties.networkAcls.defaultAction`
- **Remediation:** Set `defaultAction: "Deny"`. Use private endpoints. Add specific network rules.

---

### 8. Azure Container Registry (ACR)

#### ACR-001: Admin User Enabled
- **Severity:** HIGH
- **Description:** ACR with admin user enabled (shared credentials instead of RBAC)
- **API Calls:**
  ```
  GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ContainerRegistry/registries/{name}?api-version=2021-09-01
  ```
- **Detection:** Check `properties.adminUserEnabled == true`
- **Real Attack:** ACR admin credentials found in storage blob, used to pull images containing secrets
- **Remediation:** Disable admin user. Use Azure AD RBAC tokens. Use ACR private endpoints.

#### ACR-002: Secrets in Container Images
- **Severity:** HIGH
- **Description:** Container images stored in ACR containing secrets in filesystem
- **Real Attack:** `docker run IMAGE cat /root/flag.txt` revealed sensitive data
- **Remediation:** Scan images with Trivy/Snyk. Don't store secrets in container filesystems.

---

### 9. Azure SQL Database

#### SQL-001: SQL Authentication Enabled
- **Severity:** HIGH
- **Description:** Azure SQL server with SQL authentication enabled (should be AAD-only)
- **API Calls:**
  ```
  GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{name}?api-version=2021-02-01
  ```
- **Detection:** Check `properties.administrators.azureADOnlyAuthentication == false`
- **Real Attack:** SQL credentials found in web app connection string, used to query sensitive data
- **Remediation:** Enable Azure AD-only authentication. Use managed identities for database access.

#### SQL-002: Overly Permissive Firewall Rules
- **Severity:** HIGH
- **Description:** SQL firewall rules with `0.0.0.0` (allow all Azure) or broad IP ranges
- **API Calls:**
  ```
  GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{name}/firewallRules?api-version=2021-02-01
  ```
- **Detection:** Flag rules with `startIpAddress: "0.0.0.0"` and `endIpAddress: "0.0.0.0"` or `"255.255.255.255"`
- **Remediation:** Use private endpoints. Restrict to specific IP ranges. Remove "allow all Azure" rules.

---

### 10. Azure Web Apps

#### WEBAPP-001: SCM Basic Auth Enabled
- **Severity:** MEDIUM
- **Description:** Kudu/SCM site accessible with basic authentication (publishing credentials)
- **API Calls:**
  ```
  GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{name}/config/web?api-version=2021-02-01
  ```
- **Detection:** Check `properties.scmBasicAuthPublishingEnabled == true`
- **Real Attack:** Publishing credentials extracted via ARM API, used to access Kudu SCM API and read source code
- **Remediation:** Disable basic auth for App Service. Use RBAC-only deployment.

#### WEBAPP-002: Connection Strings with Credentials
- **Severity:** HIGH
- **Description:** SQL/storage connection strings with embedded credentials in app settings
- **API Calls:**
  ```
  POST /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{name}/config/connectionstrings/list?api-version=2021-02-01
  ```
- **Detection:** Check for `SQLAZURECONNSTR_*` settings containing `Password=` or `Pwd=`
- **Real Attack:** `SQLAZURECONNSTR_Database` contained SQL credentials `db_read / gAegH!324fAG!#1fht`
- **Remediation:** Use Managed Identity for database auth. Use Key Vault references.

#### WEBAPP-003: Deployment Packages in Accessible Storage
- **Severity:** HIGH
- **Description:** Function App deployment packages (SquashFS) accessible in blob storage
- **Real Attack:** `scm-releases` container accessible with SAS token, contained full Function App source code
- **Remediation:** Restrict `scm-releases` container access. Use private endpoints for deployment storage.

---

### 11. Cross-Cutting Patterns

#### PATTERN-001: Token/Session Theft Chain
Azure CLI tokens cached on disk → refresh token → impersonate other users → access their resources
- **Real Attack:** `C:\users\RyanMacdonal_*\.azure\accessTokens.json` → refresh token → storage access → Cloud Shell .img

#### PATTERN-002: Credential Reuse Across Services
Same password used for DSC config, WinRM, SSH, and PowerShell remoting
- **Real Attack:** `dsc / GNtrRHgfefbFE123!@#!` worked on 2 VMs + SSH + WinRM

#### PATTERN-003: Error Logs Exposing Credentials
`Invoke-AzVMRunCommand` logs contain command-line passwords in error output
- **Real Attack:** Cloud Shell error logs had `echo 'password' | sudo -S -u user 'whoami'`

---

## Azure CLI Commands Reference

```bash
# Authentication
az login -u "user@domain.com" -p 'password'
az account show

# Azure AD
az ad group list --query '[].{name:displayName, desc:description}'
az ad user list

# Automation
az rest --method get --url "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Automation/automationAccounts/{account}/runbooks/{runbook}/content?api-version=2023-11-01"

# Storage
az storage account list --query '[].{name:name, publicAccess:allowBlobPublicAccess}'
az storage account update --name ACCOUNT --allow-blob-public-access false

# VMs / Network
az vm list --query '[].{name:name, identity:identity}'
az network nsg list
az network nsg rule list --nsg-name NSG --resource-group RG

# Key Vault
az keyvault list
az keyvault show --name VAULT

# SQL
az sql server list --query '[].{name:name, aadOnly:administrators.azureAdOnlyAuthentication}'
az sql server firewall-rule list --server SERVER --resource-group RG

# Web Apps
az webapp list --query '[].{name:name, identity:identity}'
az functionapp list

# IMDS
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```
