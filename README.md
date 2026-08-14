# WinSec Auditor

![C#](https://img.shields.io/badge/c%23-%23239120.svg?style=for-the-badge&logo=csharp&logoColor=white)
![.NET](https://img.shields.io/badge/.NET-5C2D91?style=for-the-badge&logo=.net&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)

**WinSec Auditor** is a stateful system-level configuration auditor built in C# and WPF. It features asynchronous policy evaluation, automated script-driven mitigation of OS vulnerabilities, and local metric persistence for continuous security posture monitoring.

---

##  Platform Overview



### Security Dashboard
<img width="1900" height="976" alt="image" src="https://github.com/user-attachments/assets/44247c93-9a7f-4f17-8b62-4fa89e383462" />

*Real-time security score, KPIs, and detailed finding evaluations.*

### Scan History & Telemetry
<img width="1906" height="967" alt="image" src="https://github.com/user-attachments/assets/8dbbfe51-e3a0-48b1-a92c-4d3f385cb722" />

*Local persistence via SQLite, tracking posture evolution and compliance trendlines over time.*

### Hardening Center
<img width="1901" height="973" alt="image" src="https://github.com/user-attachments/assets/ca852897-ef9a-4609-a683-212181bb63f7" />

*Automated, single-click script-driven remediations for detected vulnerabilities.*

### HTML Posture Reports
<img width="1837" height="894" alt="image" src="https://github.com/user-attachments/assets/b327fc20-bf74-4bd6-a28a-53b518cffd48" />

*Offline-ready, exportable security posture reports detailing passed controls and critical failures.*

---

##  Core Architecture & Features

The platform is engineered to interact directly with underlying Windows subsystems without relying on external bloatware. 

* **Asynchronous Auditing Engine:** Runs security checks on background threads to prevent UI blocking, aggregating data from the registry, WMI, and local security policies.
* **Embedded PowerShell Integration:** Utilizes a dedicated `IPowerShellEngine` to dynamically execute automation scripts for both scanning and remediation.
* **Automated Mitigation:** Maps detected vulnerabilities to actionable fixes, allowing administrators to patch configurations (e.g., blocking vulnerable ports, enforcing UAC) with a single click.
* **Historical Telemetry:** Persists scan history and configuration drift over time using an embedded SQLite database.

## 🛡️ Security Modules Evaluated

The auditing engine evaluates multiple critical vectors of the Windows OS:

1. **Windows Defender & AntiMalware:** Validates real-time protection and service integrity.
2. **Network & Firewall:** Audits open ports (e.g., SMB 445, RDP 3389) and active firewall profiles.
3. **System Access (UAC):** Ensures Local Security Authority (LSA) and User Account Control configurations enforce least privilege.
4. **Boot Integrity:** Checks for Secure Boot validation and BitLocker drive encryption status.
5. **Execution Policies:** Analyzes PowerShell execution restrictions and SmartScreen enforcement.

##  Getting Started

### Prerequisites
* Windows 10 or Windows 11
* .NET SDK installed (for compiling from source)
* **Administrator Privileges:** The application *must* be run as Administrator to query system-level metrics and apply mitigations.

### Build & Run
1. Clone the repository:
   ```bash
   git clone [https://github.com/YourUsername/WinSecAuditor.git](https://github.com/YourUsername/WinSecAuditor.git)
