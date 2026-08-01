# MITRE ATT&CK Mapping

All rules in this library are mapped to the [MITRE ATT&CK for Cloud](https://attack.mitre.org/matrices/enterprise/cloud/) framework.

| Rule ID | Rule Name | Tactic | Technique ID | Technique Name | Data Source |
|---|---|---|---|---|---|
| CA-001 | Brute Force Sign-in Failures | Credential Access | T1110.001 | Brute Force: Password Guessing | SigninLogs |
| CA-002 | Password Spray Detection | Credential Access | T1110.003 | Brute Force: Password Spraying | SigninLogs |
| CA-003 | MFA Fatigue / Push Flooding | Credential Access | T1621 | MFA Request Generation | SigninLogs |
| CA-004 | Successful Sign-in After Multiple Failures | Credential Access | T1110.001 | Brute Force: Password Guessing | SigninLogs |
| CA-005 | First-Time Key Vault Secret Access | Credential Access | T1555 | Credentials from Password Stores | AzureDiagnostics |
| CA-006 | Legacy Authentication Protocol Used | Credential Access | T1078 | Valid Accounts | SigninLogs |
| IA-001 | Impossible Travel | Initial Access | T1078 | Valid Accounts | SigninLogs |
| IA-002 | Sign-in from New Country | Initial Access | T1078 | Valid Accounts | SigninLogs |
| IA-003 | Sign-in After Long Inactivity | Initial Access | T1078 | Valid Accounts | SigninLogs |
| PE-001 | New Owner Role Assignment | Privilege Escalation | T1098.003 | Additional Cloud Roles | AzureActivity |
| PE-002 | PIM Role Activation | Privilege Escalation | T1098.003 | Additional Cloud Roles | AuditLogs |
| PE-003 | User Added to Privileged Group | Privilege Escalation | T1098 | Account Manipulation | AuditLogs |
| LM-001 | Unusual Service Principal Activity | Lateral Movement | T1078.004 | Valid Accounts: Cloud Accounts | AADServicePrincipalSignInLogs |
| LM-002 | Service Principal Credential Added | Lateral Movement | T1098.001 | Additional Cloud Credentials | AuditLogs |
| EX-001 | Large Blob Download | Exfiltration | T1530 | Data from Cloud Storage | StorageBlobLogs |
| EX-002 | Bulk Storage Read Operations | Exfiltration | T1530 | Data from Cloud Storage | StorageBlobLogs |
| PS-001 | Suspicious OAuth App Consent | Persistence | T1098.003 | Additional Cloud Roles | AuditLogs |
| PS-002 | New Service Principal Created with Credentials | Persistence | T1136.003 | Create Account: Cloud Account | AuditLogs |
| PS-003 | Guest User Invited | Persistence | T1136 | Create Account | AuditLogs |
| PS-004 | App Registration Redirect URI Modified | Persistence | T1098 | Account Manipulation | AuditLogs |
| PS-005 | Federated Identity Credential Added | Persistence | T1098.001 | Additional Cloud Credentials | AuditLogs |
| DE-001 | Diagnostic Settings Deleted | Defense Evasion | T1562.008 | Disable Cloud Logs | AzureActivity |
| DE-002 | Azure Policy Deleted or Disabled | Defense Evasion | T1562 | Impair Defenses | AzureActivity |
| DE-003 | Conditional Access Policy Modified | Defense Evasion | T1562.006 | Indicator Blocking | AuditLogs |
| DE-004 | Defender Alert Suppression Created | Defense Evasion | T1562.001 | Disable or Modify Tools | AzureActivity |
| DE-005 | NSG Open Rule Added | Defense Evasion | T1562.007 | Disable Cloud Firewall | AzureActivity |
| DI-001 | Key Vault Enumeration | Discovery | T1580 | Cloud Infrastructure Discovery | AzureDiagnostics |
| DI-002 | Excessive Resource Enumeration | Discovery | T1526 | Cloud Service Discovery | AzureActivity |
| EC-001 | VM Extension Silently Installed | Execution | T1059 | Command and Scripting Interpreter | AzureActivity |
| EC-002 | Automation Runbook Created or Modified | Execution | T1059 | Command and Scripting Interpreter | AzureActivity |
| IM-001 | Mass Resource Deletion | Impact | T1485 | Data Destruction | AzureActivity |
| IM-002 | Subscription Ownership Transfer | Impact | T1098 | Account Manipulation | AzureActivity |

## Tactic Coverage

| Tactic | Rules |
|---|---|
| Credential Access | CA-001, CA-002, CA-003, CA-004, CA-005, CA-006 |
| Initial Access | IA-001, IA-002, IA-003 |
| Privilege Escalation | PE-001, PE-002, PE-003 |
| Lateral Movement | LM-001, LM-002 |
| Exfiltration | EX-001, EX-002 |
| Persistence | PS-001, PS-002, PS-003, PS-004, PS-005 |
| Defense Evasion | DE-001, DE-002, DE-003, DE-004, DE-005 |
| Discovery | DI-001, DI-002 |
| Execution | EC-001, EC-002 |
| Impact | IM-001, IM-002 |
