# Zero Standing Privilege Gateway for Azure

![ZSP Gateway Architecture](https://nineliveszerotrust.com/images/blog/zsp-azure/zsp-gateway-architecture.svg)

> **Companion repo for the blog post: [Just-In-Time Access for AI Agents: Building a ZSP Gateway in Azure](https://nineliveszerotrust.com/blog/zero-standing-privilege-azure/)**

A serverless gateway that grants time-bounded Azure permissions to AI agents, automation workflows, and service principals. Implements the **Zero Standing Privilege** pattern - identities start with zero permissions and receive temporary access on demand.

## The Problem

Modern Azure environments contain 50-100 non-human identities (NHIs) per human user. Most have standing access they use for only minutes per day:

- A backup service principal with 24/7 Key Vault access for a 5-minute nightly job
- A CI/CD pipeline with permanent Contributor rights for occasional deployments
- An AI coding assistant with broad permissions "just in case"

Standing privileges create unnecessary attack surface. If a service principal is compromised, attackers inherit all its permissions immediately.

## The Solution

A centralized gateway that grants temporary, scoped access:

```
Access Request → ZSP Gateway → RBAC Assignment (time-bounded)
                     │
                     ├── Durable Functions (scheduled revocation)
                     └── Log Analytics (audit trail)
```

The gateway:
- Validates requests and creates scoped Azure RBAC role assignments
- Schedules automatic revocation via Durable Functions timers
- Logs all grants/revocations to Log Analytics with workflow IDs

---

## Use Cases

| Identity Type | Example | Access Pattern |
|--------------|---------|----------------|
| **AI Coding Agent** | Claude, Copilot | 30-min Contributor access for deployments |
| **Backup Automation** | Nightly backup SP | 10-min Key Vault Secrets User during backup window |
| **Security Scanner** | Scheduled vulnerability scan | 60-min Reader access every 6 hours |
| **Human Admin** | IT administrator | 15-min Intune Admin via Entra group membership |
| **CI/CD Pipeline** | GitHub Actions | Scoped access only during deployment |

---

## Prerequisites

- Azure subscription with Owner access
- Azure CLI configured (`az login`)
- PowerShell 7+ (`pwsh`)
- Entra ID P1 or P2 license (for group-based role assignment)

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/j-dahl7/zsp-azure-lab.git
cd zsp-azure-lab
```

### 2. Deploy

```powershell
./scripts/Deploy-Lab.ps1
```

Or with custom settings:

```powershell
./scripts/Deploy-Lab.ps1 -ProjectName "my-zsp" -Location "westus2"
```

The script will:
1. Deploy Azure resources via Bicep (Resource Group, Key Vault, Storage, Function App, Log Analytics, DCE)
2. Create Entra ID objects (ZSP groups, directory role assignments, backup SP)
3. Create the `ZSPAudit_CL` custom table and Data Collection Rule
4. Grant Graph API permissions and RBAC roles to the Function App managed identity
5. Deploy Function code and run smoke tests

### 3. Test NHI Access

Request temporary Key Vault access for a service principal:

```bash
curl -X POST "$FUNCTION_URL/api/nhi-access" \
  -H "Content-Type: application/json" \
  -d '{
    "sp_object_id": "BACKUP_SP_OBJECT_ID",
    "scope": "/subscriptions/.../providers/Microsoft.KeyVault/vaults/zsp-lab-kv",
    "role": "Key Vault Secrets User",
    "duration_minutes": 10,
    "workflow_id": "manual-test"
  }'
```

Response:
```json
{
  "status": "granted",
  "assignment_id": "/subscriptions/.../roleAssignments/...",
  "expires_at": "2026-01-27T21:06:16.156493",
  "duration_minutes": 10
}
```

After 10 minutes, the role assignment is automatically revoked.

---

## Architecture

**Components:**

- **ZSP Function Gateway** - Azure Function App with two endpoints:
  - `/api/nhi-access` - Grants RBAC role assignments to service principals
  - `/api/admin-access` - Grants Entra group membership to human admins
- **Durable Functions** - Schedules and executes automatic revocation
- **Log Analytics** - Custom `ZSPAudit_CL` table for audit trail
- **Data Collection Endpoint/Rule** - Ingests audit events from the Function

---

## File Structure

```
zsp-azure-lab/
├── README.md
├── bicep/
│   ├── main.bicep            # Main orchestrator
│   ├── main.bicepparam       # Parameter template
│   └── modules/
│       ├── core.bicep        # RG, Key Vault, Storage
│       ├── function.bicep    # Function App, Plan, Insights
│       └── monitoring.bicep  # Log Analytics, DCE
├── scripts/
│   ├── Deploy-Lab.ps1        # Main deployment script
│   ├── Deploy-Azure.ps1      # Bicep deployment
│   ├── Setup-EntraID.ps1     # Entra ID objects
│   ├── Grant-Permissions.ps1 # Graph API permissions
│   ├── Configure-Function.ps1# Function settings
│   └── Test-Lab.ps1          # Smoke tests
└── function/
    ├── function_app.py       # Main function handlers
    ├── nhi_access.py         # NHI ZSP logic
    ├── admin_access.py       # Human ZSP logic
    ├── audit.py              # Logging utilities
    ├── requirements.txt
    └── host.json
```

---

## Supported Roles

| Role | Use Case |
|------|----------|
| Key Vault Secrets User | Read secrets during backup |
| Key Vault Secrets Officer | Manage secrets |
| Key Vault Reader | Read vault metadata |
| Storage Blob Data Reader | Read backup data |
| Storage Blob Data Contributor | Write backup data |
| Reader | Read-only access to resources |
| Contributor | Full resource management |

---

## Cleanup

```bash
# Delete Azure resources
az group delete --name zsp-lab-rg --yes

# Delete Entra ID objects
az ad group delete --group "SG-Intune-Admins-ZSP"
az ad group delete --group "SG-Security-Reader-ZSP"
az ad app delete --id "<backup-app-id>"
```

---

## Roadmap

- **Terraform module** - Coming soon

---

## Resources

- [Blog: Just-In-Time Access for AI Agents](https://nineliveszerotrust.com/blog/zero-standing-privilege-azure/)
- [Lab Guide with KQL Queries](https://nineliveszerotrust.com/labs/zsp-azure/)
- [Microsoft Graph PIM APIs](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-apis)
- [Azure Durable Functions](https://learn.microsoft.com/en-us/azure/azure-functions/durable/durable-functions-overview)

---

## License

MIT License - See [LICENSE](LICENSE) for details.
