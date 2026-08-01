# KQL Detection Rules Library

A production-quality library of 32 KQL (Kusto Query Language) detection rules for Microsoft Sentinel and Microsoft Defender for Cloud, mapped to the MITRE ATT&CK for Cloud framework.

Each rule is written to be usable as-is in a Sentinel Analytics Rule or Log Analytics query, with tuning notes and false positive guidance included directly in the query file.

## Rules

| ID | Category | Rule | Severity | Data Source |
|---|---|---|---|---|
| CA-001 | Credential Access | Brute Force Sign-in Failures | HIGH | SigninLogs |
| CA-002 | Credential Access | Password Spray Detection | HIGH | SigninLogs |
| CA-003 | Credential Access | MFA Fatigue / Push Flooding | HIGH | SigninLogs |
| CA-004 | Credential Access | Successful Sign-in After Multiple Failures | CRITICAL | SigninLogs |
| CA-005 | Credential Access | First-Time Key Vault Secret Access | MEDIUM | AzureDiagnostics |
| CA-006 | Credential Access | Legacy Authentication Protocol Used | HIGH | SigninLogs |
| IA-001 | Initial Access | Impossible Travel | HIGH | SigninLogs |
| IA-002 | Initial Access | Sign-in from New Country | MEDIUM | SigninLogs |
| IA-003 | Initial Access | Sign-in After Long Inactivity | MEDIUM | SigninLogs |
| PE-001 | Privilege Escalation | New Owner Role Assignment at Subscription Scope | CRITICAL | AzureActivity |
| PE-002 | Privilege Escalation | PIM Privileged Role Activation | MEDIUM | AuditLogs |
| PE-003 | Privilege Escalation | User Added to Privileged Group | HIGH | AuditLogs |
| LM-001 | Lateral Movement | Unusual Service Principal Sign-in Activity | HIGH | AADServicePrincipalSignInLogs |
| LM-002 | Lateral Movement | Service Principal Credential Added | HIGH | AuditLogs |
| EX-001 | Exfiltration | Large Blob Download | HIGH | StorageBlobLogs |
| EX-002 | Exfiltration | Bulk Storage Read Operations | MEDIUM | StorageBlobLogs |
| PS-001 | Persistence | Suspicious OAuth App Consent | HIGH | AuditLogs |
| PS-002 | Persistence | New Service Principal Created with Credentials | MEDIUM | AuditLogs |
| PS-003 | Persistence | Guest User Invited to Tenant | LOW | AuditLogs |
| PS-004 | Persistence | App Registration Redirect URI Modified | HIGH | AuditLogs |
| PS-005 | Persistence | Federated Identity Credential Added | HIGH | AuditLogs |
| DE-001 | Defense Evasion | Diagnostic Settings Deleted | HIGH | AzureActivity |
| DE-002 | Defense Evasion | Azure Policy Deleted or Disabled | HIGH | AzureActivity |
| DE-003 | Defense Evasion | Conditional Access Policy Modified or Deleted | CRITICAL | AuditLogs |
| DE-004 | Defense Evasion | Defender for Cloud Alert Suppression Created | HIGH | AzureActivity |
| DE-005 | Defense Evasion | NSG Open Inbound Rule Added | HIGH | AzureActivity |
| DI-001 | Discovery | Key Vault Enumeration | MEDIUM | AzureDiagnostics |
| DI-002 | Discovery | Excessive Resource Enumeration | MEDIUM | AzureActivity |
| EC-001 | Execution | VM Extension Silently Installed | HIGH | AzureActivity |
| EC-002 | Execution | Automation Runbook Created or Modified | HIGH | AzureActivity |
| IM-001 | Impact | Mass Resource Deletion | CRITICAL | AzureActivity |
| IM-002 | Impact | Subscription Ownership Transfer | CRITICAL | AzureActivity |

## Prerequisites

The following log sources must be connected to your Log Analytics workspace / Microsoft Sentinel:

| Log Source | Required By | How to Enable |
|---|---|---|
| SigninLogs | CA-001 to CA-006, IA-001 to IA-003 | Entra ID → Diagnostic Settings → Send to Log Analytics |
| AuditLogs | PE-002, PE-003, LM-002, PS-001 to PS-005, DE-003 | Entra ID → Diagnostic Settings → Send to Log Analytics |
| AzureActivity | PE-001, DE-001, DE-002, DE-004, DE-005, DI-002, EC-001, EC-002, IM-001, IM-002 | Subscription → Activity Log → Export to Log Analytics |
| AADServicePrincipalSignInLogs | LM-001 | Entra ID → Diagnostic Settings (optional logs) |
| StorageBlobLogs | EX-001, EX-002 | Storage Account → Diagnostic Settings → StorageRead |
| AzureDiagnostics (Key Vault) | CA-005, DI-001 | Key Vault → Diagnostic Settings → AuditEvent |

## Usage

### Run directly in Log Analytics / Sentinel

1. Open Microsoft Sentinel → Logs (or Log Analytics workspace → Logs)
2. Copy the contents of any `.kql` file
3. Paste into the query editor
4. Adjust thresholds and filters as noted in the tuning section
5. Run

### Create a Sentinel Analytics Rule

1. Microsoft Sentinel → Analytics → Create → Scheduled query rule
2. Paste the KQL query
3. Set the rule name, description, MITRE tactic, and severity from the rule header
4. Configure the query schedule (recommended: run every 5-15 minutes, look back 1 hour)
5. Set alert threshold: generate alert when results > 0

## Repository Structure

```
rules/
  credential-access/
    CA-001_brute-force-signin-failures.kql
    CA-002_password-spray.kql
    CA-003_mfa-fatigue.kql
    CA-004_success-after-failures.kql
    CA-005_first-time-keyvault-access.kql
    CA-006_legacy-auth-protocol.kql
  initial-access/
    IA-001_impossible-travel.kql
    IA-002_signin-new-country.kql
    IA-003_signin-after-inactivity.kql
  privilege-escalation/
    PE-001_owner-role-assignment.kql
    PE-002_pim-role-activation.kql
    PE-003_user-added-privileged-group.kql
  lateral-movement/
    LM-001_unusual-service-principal-activity.kql
    LM-002_service-principal-credential-added.kql
  exfiltration/
    EX-001_large-blob-download.kql
    EX-002_bulk-storage-reads.kql
  persistence/
    PS-001_suspicious-oauth-consent.kql
    PS-002_new-service-principal-credentials.kql
    PS-003_guest-user-invited.kql
    PS-004_app-redirect-uri-modified.kql
    PS-005_federated-identity-credential-added.kql
  defense-evasion/
    DE-001_diagnostic-settings-deleted.kql
    DE-002_azure-policy-deleted.kql
    DE-003_conditional-access-modified.kql
    DE-004_defender-alert-suppression.kql
    DE-005_nsg-open-rule-added.kql
  discovery/
    DI-001_keyvault-enumeration.kql
    DI-002_resource-enumeration.kql
  execution/
    EC-001_vm-extension-installed.kql
    EC-002_automation-runbook-modified.kql
  impact/
    IM-001_mass-resource-deletion.kql
    IM-002_subscription-ownership-transfer.kql

MITRE_MAPPING.md
README.md
```

## Rule File Format

Every `.kql` file follows a consistent header format:

```
// Rule ID     : <ID>
// Name        : <Name>
// MITRE Tactic: <Tactic>
// MITRE Tech  : <TechniqueID> — <TechniqueName>
// Data Source : <LogTable>
// Severity    : <CRITICAL|HIGH|MEDIUM|LOW>
// Author      : Neel Kotnis
//
// Description:
// False Positives:
// Tuning Notes:
```

## Related Projects

- [azure-security-auditor](https://github.com/neelkotnis/azure-security-auditor) — CLI tool to audit Azure security posture (RBAC, NSGs, storage, identity, compute, encryption, monitoring)
- [aws-iam-security-auditor](https://github.com/neelkotnis/aws-iam-security-auditor) — CLI tool to audit AWS IAM security configurations
