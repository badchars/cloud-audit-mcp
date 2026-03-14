# Cloud Audit MCP

## Project Context

Bu proje hackbrowser-mcp'den sonra ikinci MCP projesi olarak planlandı. hackbrowser-mcp browser-based security testing yapıyor (39 tool, multi-container Firefox, injection testing). cloud-audit-mcp ise AWS/Azure/GCP misconfiguration detection yapacak — AI agent'a cloud API'lerini MCP üzerinden vererek.

### Neden MCP?

Prowler, ScoutSuite, CloudSploit gibi araçlar var ama hepsi CLI/dashboard. Hiçbiri AI agent'a MCP üzerinden kontrol vermiyor. Fark: Prowler çalıştırırsın 200 sayfalık rapor gelir, sen okursun. Cloud audit MCP'de agent direkt cloud API'lerini çağırır, bulguları önceliklendirir, fix önerir.

### Hedef Kullanım

```
User: "AWS hesabımda en kritik 5 misconfiguration'ı bul ve nasıl fix edileceğini söyle"

Agent: → AWS API'lerini çağırır (S3, IAM, SG, CloudTrail, RDS)
       → Bulguları severity'ye göre sıralar
       → Her biri için fix komutu verir
```

### Taranacak Alanlar

**AWS:**
- S3 bucket public access, ACL, policy
- IAM: MFA, over-permissive policies, privilege escalation paths
- Security Groups: 0.0.0.0/0 açık portlar
- Lambda: env var'larda plaintext secret
- CloudTrail: logging açık mı?
- RDS/ElastiCache: public access
- EBS: unencrypted volumes

**Azure:**
- Storage account anonymous access
- NSG kuralları
- Managed Identity over-permission
- Key Vault access policy

**GCP:**
- Service account key export
- Firewall rules
- BigQuery public dataset
- Cloud Storage bucket ACL

## Technical Stack

- **Runtime:** Bun + TypeScript (hackbrowser-mcp ile aynı)
- **Protocol:** MCP (stdio transport)
- **SDK:** @modelcontextprotocol/sdk
- **Cloud SDKs:** @aws-sdk/*, @azure/identity + @azure/arm-*, @google-cloud/*
- **Architecture:** hackbrowser-mcp pattern'i takip et — tools.ts (Zod schema), mcp-server.ts (stdio), ayrı provider dosyaları

## Related Projects

- **hackbrowser-mcp:** https://github.com/badchars/hackbrowser-mcp — Browser-based security testing MCP (kardeş proje)
- **recon0:** https://github.com/badchars/recon0 — Bug bounty recon pipeline
- **vuln-research:** LLM-powered vulnerability analysis (Bun + TypeScript)

## Developer

- **Author:** Orhan Yildirim
- **GitHub:** https://github.com/badchars
- **Book:** [Agentic AI for Offensive Cybersecurity](https://www.amazon.com/dp/B0GFD44D84)
- **License:** MIT

## Rules

- Runtime: Bun (Node.js değil)
- Dil: TypeScript strict mode
- Dependency az tut — sadece cloud SDK'lar + MCP SDK
- Her cloud provider ayrı modülde (aws/, azure/, gcp/)
- Tool isimleri: `aws_check_s3`, `azure_check_storage`, `gcp_check_buckets` gibi provider prefix'li
- Zod schema her tool için zorunlu
- Türkçe yorum yazma, İngilizce kod + yorum
- README: hackbrowser-mcp kalitesinde, banner + badges + karşılaştırma tablosu
