# 🛡️ Red Team PoCs

> **A collection of offensive security research, Red Teaming techniques, adversary simulations, and Proof-of-Concepts (PoCs).**

![Red Team](https://img.shields.io/badge/Focus-Red%20Teaming-red)
![Security Research](https://img.shields.io/badge/Focus-Security%20Research-blue)
![PoCs](https://img.shields.io/badge/Content-PoCs-orange)
![MITRE ATT\&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-purple)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 📖 About

**Red-Team-POCs** is a security research repository containing Proof-of-Concept implementations, experiments, scripts, and technical demonstrations related to **Red Teaming, adversary simulation, penetration testing, malware research, Windows internals, offensive tooling, and security evasion research**.

The primary objective of this repository is to understand how offensive techniques work at a technical level and how defenders can **detect, investigate, and mitigate** them.

This repository is intended as a continuously evolving research archive rather than a single offensive-security framework.

---

## 🎯 Research Areas

The repository may contain PoCs covering areas such as:

| Area                          | Description                                                                |
| ----------------------------- | -------------------------------------------------------------------------- |
| 🔴 **Red Teaming**            | Adversary simulation and offensive security techniques                     |
| 🪟 **Windows Internals**      | Windows APIs, processes, memory, tokens, services and execution mechanisms |
| 💉 **Process Injection**      | Research into process and thread execution techniques                      |
| 🧬 **Malware Research**       | Malware-development concepts and behavioral research                       |
| 🕵️ **Defense Evasion**       | Research into telemetry, detection and evasion mechanisms                  |
| 🔐 **Credential Access**      | Credential-related attack research in controlled environments              |
| 🌐 **Network Security**       | Network-level attack and protocol research                                 |
| 🧪 **Vulnerability Research** | Vulnerability analysis and exploit PoCs                                    |
| ☁️ **Cloud Security**         | Cloud attack paths and security testing                                    |
| 🤖 **AI / LLM Security**      | AI red teaming, LLM security and agent security research                   |
| 🔗 **Active Directory**       | AD attack-path and authentication research                                 |
| ⚙️ **Offensive Tooling**      | Small utilities and experimental security tooling                          |

> The exact categories will evolve as new research is added.

---

## 🧪 PoC Philosophy

Each PoC is intended to answer one or more technical questions:

* **How does the technique actually work?**
* **What Windows/Linux/network primitives are involved?**
* **What telemetry does the technique generate?**
* **What security controls can detect it?**
* **What assumptions does the technique rely upon?**
* **How can defenders investigate the behavior?**
* **How can the technique be mitigated?**

Where practical, PoCs should include:

```text
1. Objective
2. Technical background
3. Prerequisites
4. Lab environment
5. Implementation
6. Execution / demonstration
7. Expected behavior
8. Detection opportunities
9. Mitigation
10. References
```

---

## 🧭 MITRE ATT&CK Mapping

Where applicable, techniques are mapped to the **MITRE ATT&CK** framework.

Example:

| Technique                         | ATT&CK ID | Category                               |
| --------------------------------- | --------- | -------------------------------------- |
| Process Injection                 | `T1055`   | Defense Evasion / Privilege Escalation |
| Command and Scripting Interpreter | `T1059`   | Execution                              |
| Scheduled Task/Job                | `T1053`   | Persistence                            |
| OS Credential Dumping             | `T1003`   | Credential Access                      |
| Application Layer Protocol        | `T1071`   | Command and Control                    |

ATT&CK mappings are provided to improve understanding of the adversary behavior and associated defensive telemetry.

---

## 🔬 Research Methodology

The general research workflow is:

```text
                 ┌────────────────────┐
                 │ Research Objective │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Technical Analysis │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Lab Implementation │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ PoC Development    │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Execution & Tests  │
                 └─────────┬──────────┘
                           │
                           ▼
              ┌───────────────────────────┐
              │ Detection / Telemetry     │
              │ Analysis                  │
              └────────────┬──────────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Documentation      │
                 └────────────────────┘
```

The emphasis is on **understanding the complete attack/defense lifecycle**, rather than simply producing working offensive code.

---

## 🖥️ Lab Environment

PoCs should be executed in an isolated and controlled environment.

Recommended controls for analysis include:

* Sysmon
* Windows Event Logs
* ETW telemetry
* EDR/XDR telemetry
* Network packet capture
* Process monitoring
* PowerShell logging
* API/system-call tracing
* SIEM correlation

---

## ⚠️ Disclaimer

**This repository is intended strictly for authorized security research, education, malware analysis, penetration testing, Red Team exercises, and isolated laboratory environments.**

The PoCs contained in this repository may demonstrate techniques that can be abused against systems without authorization.

**Do not use these PoCs against systems, networks, accounts, applications, or infrastructure that you do not own or have explicit permission to test.**

You are solely responsible for ensuring that your use of this repository complies with applicable laws, regulations, contracts, and organizational policies.

The author assumes no responsibility for damage, data loss, unauthorized access, service disruption, or any other consequences resulting from misuse of the material contained within this repository.

---

## 🔐 Responsible Research

Security research should be performed with appropriate authorization and within a controlled scope.

When developing or testing a PoC:

* Use isolated laboratory environments.
* Avoid targeting third-party infrastructure.
* Use synthetic or non-sensitive credentials.
* Do not collect real user data.
* Do not deploy experimental malware outside controlled environments.
* Clearly document assumptions and limitations.
* Prefer reproducible demonstrations.
* Document defensive detection opportunities whenever possible.

---

## 📚 References

Useful resources for understanding adversary behavior and defensive validation include:

* [MITRE ATT&CK](https://attack.mitre.org/)
* [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
* [OWASP](https://owasp.org/)
* [Microsoft Security](https://www.microsoft.com/security)
* [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## 🤝 Contributions

This repository primarily serves as a personal research archive, but suggestions, improvements, research discussions, and responsible contributions are welcome.

If you discover an issue with a PoC or documentation:

1. Open an issue.
2. Clearly describe the problem.
3. Include the affected PoC.
4. Provide reproducible information where possible.
5. Avoid posting sensitive information or real-world credentials.

---

## 👤 Author

**Debajyoti Haldar**

Cybersecurity Engineer | Red Teaming | Penetration Testing | Security Research

🔗 GitHub: [@Debajyoti0-0](https://github.com/Debajyoti0-0)

---

## ⭐ Purpose

> **Understand the offensive technique.
> Understand the telemetry it creates.
> Understand how defenders can detect it.
> Then build better security.**

---

<p align="center">
  <b>🔴 Offensive Research • 🧪 Controlled Experiments • 🔵 Defensive Understanding</b>
</p>
