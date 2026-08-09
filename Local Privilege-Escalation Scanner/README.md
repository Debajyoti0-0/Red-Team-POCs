# Windows Local Privilege-Escalation Scanner

> **A read-only Windows privilege-escalation attack-surface auditor for Red Team operations, security assessments, and Windows security research.**

**`privesc-audit.ps1`** is a single-file PowerShell framework designed to identify security weaknesses that may expose a Windows host to **local privilege-escalation attack paths**.

The scanner focuses on security-sensitive objects executed under privileged Windows security contexts, including **NT AUTHORITY processes, Windows services, scheduled tasks, and registry-based execution surfaces**.

The project is designed around a simple principle:

```text
Low-Privileged Principal
        │
        ▼
Weak Access / Write Permission
        │
        ▼
Security-Sensitive Object
        │
        ▼
Privileged Execution Context
        │
        ▼
Potential Privilege-Escalation Path
```

The scanner is **read-only** and does not modify the target system.

---

## Features

### 🔎 Privileged Process & DLL Analysis

The scanner enumerates processes running under:

```text
NT AUTHORITY\SYSTEM
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
```

and analyzes their loaded modules.

For accessible processes it evaluates:

- Process ID
- Process name
- Process account
- Loaded DLLs
- DLL file paths
- DLL file ACLs
- Parent-directory permissions
- Potential writable DLL locations
- Potential DLL planting locations
- Access-denied conditions

This helps identify situations where a privileged process loads a DLL from a location that may be writable by a lower-privileged principal.

---

### ⚙️ Windows Service Auditing

The scanner audits Windows services for common privilege-escalation attack surfaces.

Current checks include:

- Service binary paths
- Service executable permissions
- Service executable directory permissions
- Service registry key permissions
- Weak registry permissions affecting service configuration
- Unquoted service paths
- Service account/security context
- Potential `ImagePath` manipulation

Example attack path:

```text
Unprivileged User
       │
       ▼
Writable Service Configuration
       │
       ▼
SYSTEM Service
       │
       ▼
Potential Local Privilege Escalation
```

---

### ⏰ Scheduled Task Auditing

The scanner identifies scheduled tasks executing under privileged accounts and analyzes their executable actions.

It evaluates:

- Scheduled task name
- Task principal
- Execution account
- Task actions
- Executable path
- Executable ACL
- Potentially writable task action targets

Particular attention is given to tasks running under:

```text
SYSTEM
LOCAL SERVICE
NETWORK SERVICE
NT AUTHORITY
```

---

### 🧩 Registry Execution Surface Analysis

The optional `-Deep` mode enables additional registry-based security checks.

The scanner currently examines execution-related registry locations including:

- `Run`
- `RunOnce`
- `AppInit_DLLs`
- Image File Execution Options (`IFEO`)
- `AlwaysInstallElevated`

The scanner differentiates between some configurations that are immediately exploitable and those that represent incomplete or lower-confidence security weaknesses.

---

### 🛡️ AlwaysInstallElevated Detection

The scanner checks both:

```text
HKLM
HKCU
```

for:

```text
AlwaysInstallElevated
```

It correctly distinguishes between:

```text
Only one policy enabled
```

and:

```text
Both HKLM and HKCU enabled
```

The latter represents the classic Windows Installer elevation misconfiguration.

---

### 🔐 Host Security Context

With `-Deep`, the scanner collects host-level security information including:

- Computer name
- Current user
- PowerShell version
- Windows version
- Windows build
- OS architecture
- Current elevation state
- UAC configuration
- `EnableLUA`
- `ConsentPromptBehaviorAdmin`
- `LocalAccountTokenFilterPolicy`

This provides context for interpreting privilege-escalation findings.

---

## Finding Model

Findings are normalized into a common structure containing information such as:

```text
Finding ID
Category
Subcategory
Severity
Confidence
Exploitability
PID
Process
Account
Target
Target Type
Identity
Rights
Trigger
Evidence
Remediation
Status
Timestamp
```

This allows the same findings to be rendered consistently across console, CSV, and HTML output.

---

## Severity

The scanner currently uses:

| Severity | Meaning |
|---|---|
| 🔴 **Critical** | Strong security boundary violation or highly significant privilege-escalation condition |
| 🟠 **High** | Significant privilege-escalation attack surface requiring validation |
| 🔵 **Medium** | Security weakness or conditional attack surface requiring additional context |
| ⚪ **Informational** | Contextual information or non-exploitable configuration |

**Important:** A finding is not automatically equivalent to a confirmed exploit.

The scanner is designed to identify **attack surfaces that require Red Team validation**.

---

# Coverage & Collection Transparency

A major design goal of the project is avoiding the misleading result:

> `0 findings = secure`

Access restrictions can prevent security tools from inspecting protected processes, files, registry keys, or other objects.

Therefore, the scanner tracks collection coverage, including:

```text
Processes discovered
Processes analyzed
Processes inaccessible

Services discovered
Services analyzed

Scheduled tasks discovered
Scheduled tasks analyzed

ACLs successfully read
ACLs inaccessible

Collection errors
```

For example:

```text
Processes Discovered     185
Processes Analyzed       174
Processes Inaccessible    11

Services Discovered      213
Services Analyzed        213

Tasks Discovered         387
Tasks Analyzed           387

ACLs Read               6421
ACLs Inaccessible         17
```

This makes the assessment result more transparent.

---

# Read-Only Design

`privesc-audit.ps1` is designed as a **read-only auditing tool**.

It performs enumeration and analysis but does not intentionally:

- Modify services
- Modify registry configuration
- Create scheduled tasks
- Replace DLLs
- Modify executables
- Create persistence
- Disable security controls
- Deploy payloads
- Dump credentials
- Exploit identified privilege-escalation conditions

The tool identifies and documents potential attack surfaces for subsequent authorized validation.

---

# Requirements

## Operating System

Designed primarily for:

```text
Windows 10
Windows 11
Windows Server
```

## PowerShell

Minimum:

```text
PowerShell 5.1
```

The script declares:

```powershell
#Requires -Version 5.1
```

For the scheduled-task audit, the Windows `ScheduledTasks` PowerShell module should be available.

---

# Installation

Clone the repository:

```powershell
git clone https://github.com/Debajyoti0-0/Red-Team-POCs.git
```

Navigate to the scanner:

```powershell
cd "Red-Team-POCs\Local Privilege-Escalation Scanner"
```

The scanner is intentionally self-contained:

```text
Local Privilege-Escalation Scanner/
└── privesc-audit.ps1
```

No external PowerShell modules written specifically for this project are required.

---

# Basic Usage

Run the scanner:

```powershell
.\privesc-audit.ps1
```

For the most complete collection currently supported:

```powershell
.\privesc-audit.ps1 -AutoElevate -Deep
```

The `-AutoElevate` option attempts to relaunch the script with administrator privileges.

Running elevated is strongly recommended because protected Windows processes and security-sensitive objects may otherwise be inaccessible.

---

# Command-Line Options

### Help

```powershell
.\privesc-audit.ps1 -Help
```

or:

```powershell
.\privesc-audit.ps1 --help
```

### Version

```powershell
.\privesc-audit.ps1 -Version
```

### Deep Audit

```powershell
.\privesc-audit.ps1 -Deep
```

Enables additional:

- Host security context
- UAC information
- AlwaysInstallElevated
- Run / RunOnce
- AppInit_DLLs
- IFEO

analysis.

### Automatic Elevation

```powershell
.\privesc-audit.ps1 -AutoElevate
```

Combine with deep analysis:

```powershell
.\privesc-audit.ps1 -AutoElevate -Deep
```

### HTML Report

```powershell
.\privesc-audit.ps1 -Format HTML
```

### CSV Report

```powershell
.\privesc-audit.ps1 -Format CSV
```

### Generate All Output Formats

```powershell
.\privesc-audit.ps1 -Format All
```

### Custom Output Directory

```powershell
.\privesc-audit.ps1 -OutputPath C:\Audit
```

### High/Critical Findings Only

```powershell
.\privesc-audit.ps1 -MinSeverity High
```

Critical only:

```powershell
.\privesc-audit.ps1 -MinSeverity Critical
```

### Exclude a Category

```powershell
.\privesc-audit.ps1 -ExcludeCategory DLL
```

Multiple categories:

```powershell
.\privesc-audit.ps1 -ExcludeCategory DLL,ScheduledTask
```

Available categories:

```text
DLL
Service
ScheduledTask
Registry
```

### Quiet Mode

```powershell
.\privesc-audit.ps1 -Quiet
```

### Disable Console Colors

Useful for output redirection:

```powershell
.\privesc-audit.ps1 -NoColor
```

### Verbose Debugging

```powershell
.\privesc-audit.ps1 -Verbose
```

---

# Example Red Team Workflow

A typical authorized Windows host assessment can follow this workflow:

### 1. Initial discovery

```powershell
.\privesc-audit.ps1 -AutoElevate
```

### 2. Deep configuration assessment

```powershell
.\privesc-audit.ps1 -AutoElevate -Deep
```

### 3. Generate an HTML report

```powershell
.\privesc-audit.ps1 -AutoElevate -Deep -Format HTML -OutputPath C:\Audit
```

### 4. Generate machine-readable results

```powershell
.\privesc-audit.ps1 -AutoElevate -Deep -Format CSV -OutputPath C:\Audit
```

### 5. Focus on significant findings

```powershell
.\privesc-audit.ps1 -AutoElevate -Deep -MinSeverity High
```

---

# Output

## Console

The default output provides a severity-oriented table containing:

```text
Category
Process / Task / Service
Account
Target
Severity
Detail
```

Severity is color-coded when console color output is enabled.

---

## CSV

CSV output is intended for:

- Further analysis
- SIEM ingestion
- Red Team evidence collection
- Reporting pipelines
- Spreadsheet analysis
- Custom automation

Example:

```text
Category,Process,Account,Target,Severity,Detail
Service (binary writable),ExampleService,LocalSystem,...,High,...
DLL (dir plantable),example.exe,SYSTEM,...,High,...
```

---

## HTML

The HTML report contains:

- Findings
- Severity
- Targets
- Accounts
- Details
- Collection coverage
- Collection errors
- Scan metadata

This makes it suitable for attaching to internal assessment documentation or using as a basis for a formal Red Team report.

---

# Execution Policy

If Windows prevents PowerShell scripts from running because of the system's execution policy, the script itself cannot execute code to change that policy.

For a one-time lab/assessment execution:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\privesc-audit.ps1
```

This applies the bypass to that PowerShell process and does not permanently change the machine's execution-policy configuration.

When using:

```powershell
-AutoElevate
```

the script also handles its elevated child process using an execution-policy bypass.

---

# Architecture

Although the project intentionally consists of **one PowerShell file**, the implementation is internally organized into functional components:

```text
privesc-audit.ps1
│
├── Configuration / Parameters
├── Logging
├── Coverage Tracking
├── Collection Error Tracking
├── Finding Normalization
├── Retry / Error Handling
├── Privileged Process Analysis
│   ├── Process ownership
│   ├── Loaded DLLs
│   ├── DLL ACLs
│   └── DLL directory permissions
│
├── Service Analysis
│   ├── Service binaries
│   ├── Service registry keys
│   └── Unquoted service paths
│
├── Scheduled Task Analysis
│   └── Privileged task actions
│
├── Host Security Context
│   └── UAC configuration
│
├── Registry Execution Surfaces
│   ├── Run
│   ├── RunOnce
│   ├── AppInit_DLLs
│   └── IFEO
│
├── AlwaysInstallElevated
│
└── Reporting
    ├── Console
    ├── CSV
    └── HTML
```

---

# Detection Philosophy

The scanner is intentionally designed around **attack-surface analysis rather than blind vulnerability matching**.

For example:

```text
Writable File
```

does not automatically mean:

```text
Privilege Escalation
```

The security significance depends on:

```text
Who can write?
       +
What can be modified?
       +
Who executes it?
       +
When does it execute?
       +
Can the attacker trigger it?
```

Therefore, findings should always be manually validated during an authorized Red Team engagement.

---

# Known Limitations

This project is actively evolving.

The current version should **not** be considered a complete Windows privilege-escalation detection engine.

Areas that require additional validation or future development include:

- Full effective-access calculation through complex group membership
- Advanced DLL search-order resolution
- Comprehensive DLL side-loading analysis
- Service configuration security-descriptor analysis
- Service `ServiceDll` analysis
- Service triggerability analysis
- Scheduled-task registration ACL analysis
- Scheduled-task XML security analysis
- PATH hijacking analysis
- COM/DCOM attack-surface analysis
- WMI permanent event subscription analysis
- Named-pipe security analysis
- Advanced token/impersonation analysis
- Reparse-point attack-path correlation
- Comprehensive AppLocker/WDAC integration
- Advanced attack-path correlation
- More extensive false-positive reduction
- Cross-version Windows behavior differences

These limitations are intentionally documented so that a scan result is not interpreted as proof that a Windows host is free of local privilege-escalation vulnerabilities.

---

# Security Considerations

This tool is intended for:

- Authorized penetration testing
- Red Team operations
- Purple Team exercises
- Windows security research
- Malware-analysis laboratories
- Defensive security assessments
- CTF/lab environments
- Security engineering research

Only run the scanner on systems you own or have explicit authorization to assess.

The scanner itself is designed to perform **read-only enumeration and analysis**.

---

# Roadmap

Planned areas of development include:

```text
[ ] Effective permission engine
[ ] Token privilege analysis
[ ] Advanced service security analysis
[ ] ServiceDll detection
[ ] DLL search-order analysis
[ ] DLL side-loading analysis
[ ] PATH hijacking detection
[ ] Scheduled-task ACL analysis
[ ] COM/DCOM analysis
[ ] WMI permanent subscription analysis
[ ] Named-pipe analysis
[ ] Reparse-point analysis
[ ] Advanced attack-path correlation
[ ] Improved risk scoring
[ ] Improved false-positive reduction
[ ] Expanded Windows version compatibility
```

---

# Why This Project?

Most basic Windows privilege-escalation scripts enumerate individual misconfigurations.

This project takes a different approach:

```text
Enumeration
     ↓
Permission Analysis
     ↓
Privileged Execution Context
     ↓
Attack Surface
     ↓
Evidence
     ↓
Risk Classification
```

The long-term objective is to build a **high-signal Windows local privilege-escalation attack-surface auditor** that helps a Red Team operator quickly understand where meaningful privilege boundaries may exist on a host.

---

# Project Status

**Status:** Active Development

**Current implementation:** Single-file PowerShell auditor

**Primary platform:** Windows

**Language:** PowerShell

**Minimum PowerShell:** 5.1

**Operating mode:** Read-only

---

# Author

**Debajyoti Haldar**

Cyber Security / Red Team / Application Security

GitHub:

[Debajyoti0-0](https://github.com/Debajyoti0-0)

Repository:

[Red-Team-POCs — Local Privilege-Escalation Scanner](https://github.com/Debajyoti0-0/Red-Team-POCs/tree/main/Local%20Privilege-Escalation%20Scanner)

---

# Disclaimer

This project is provided for **authorized security testing, research, and educational purposes**.

The author is not responsible for misuse, unauthorized access, damage, data loss, service disruption, or other consequences resulting from the use of this tool.

Always obtain appropriate authorization before performing security assessments.

---

## ⭐ If You Find This Useful

If this project helps with your Windows security research, Red Team lab, or authorized assessment:

- ⭐ Star the repository
- 🐛 Report bugs
- 💡 Suggest improvements
- 🔬 Submit research findings
- 🔧 Contribute improvements

Security tooling improves through continuous testing, validation, and peer review.