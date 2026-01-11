# Threat Detection & Response Lab: Sysmon & MITRE ATT&CK 🛡️

![Category](https://img.shields.io/badge/Category-Blue%20Team-blue)
![Tools](https://img.shields.io/badge/Tools-Sysmon%20%7C%20Process%20Hacker%20%7C%20Mimikatz-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

## 📖 Overview
This repository documents my hands-on research into **Endpoint Detection and Response (EDR)** techniques. The project simulates real-world attack scenarios based on the **MITRE ATT&CK Framework** to analyze malicious behavior and develop detection logic using **Sysmon** (System Monitor).

As a Computer Science student at **Ho Chi Minh City University of Technology (HCMUT)**, this project serves as a practical application of Operating System internals and Network Security concepts.

## 🎯 Objectives
* **Attack Simulation:** Execute Red Team techniques (DLL Hijacking, Injection, Credential Dumping) in a controlled environment.
* **Log Analysis:** Investigate Windows Event Logs (specifically Sysmon) to identify forensic artifacts.
* **Detection Engineering:** Develop "Behavioral-based" detection logic rather than relying on simple file signatures.

## 🛠️ Lab Environment
* **Operating System:** Windows 10/11 Enterprise (Virtual Machine).
* **Telemetry:** Sysmon (Configured with [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) / OlafHartong profile).
* **Analysis Tools:** Windows Event Viewer, Process Hacker 2, PowerShell.
* **Attack Tools:** Mimikatz, Metasploit/Empire (Simulated scripts), Custom C++ DLLs.

## 🗂️ Project Modules
This lab is divided into specific attack scenarios. Click on each module for detailed analysis and evidence.

| Module | Attack Technique | MITRE ID | Key Learning |
| :--- | :--- | :--- | :--- |
| **[01. DLL Hijacking](./01-DLL-Hijacking)** | Hijack Execution Flow | [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | Detected unsigned module loading & path anomalies (Event ID 7). |
| **[02. Process Injection](./02-Process-Injection)** | Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | Identified `.NET/CLR` loading into unmanaged processes like `spoolsv.exe`. |
| **[03. Credential Dumping](./03-Credential-Dumping)** | OS Credential Dumping | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Detected `lsass.exe` memory access with `0x1010` rights (Event ID 10). |
| **[04. Advanced ETW Hunting](./04-Advanced-ETW-Hunting)** | Parent PID Spoofing & BYOL | [T1134.004](https://attack.mitre.org/techniques/T1134/004/) | Used **SilkETW** to expose spoofed parent processes and identify .NET Assembly names (e.g., `Seatbelt`) in memory. |

## 🚀 Key Takeaways
Through this project, I have gained deep insights into:
* **Windows Internals:** Understanding PE structure, DLL search order, and Memory management (Managed vs. Unmanaged code).
* **Log Analysis:** Proficiency in filtering and interpreting Sysmon Event IDs (1, 7, 10, etc.).
* **Threat Hunting:** Moving from reactive monitoring to proactive hunting by looking for anomalies in process lineage and access rights.
* **Advanced Telemetry (ETW):** Learned that user-mode logs (Sysmon) can be spoofed. Validated "Ground Truth" data using Kernel-level tracing to detect sophisticated evasion techniques (Parent PID Spoofing).

## ⚠️ Disclaimer
* All attacks were performed in a strictly isolated virtual environment.
* Malware samples and tools (like Mimikatz) are used solely for educational and defensive research purposes.

