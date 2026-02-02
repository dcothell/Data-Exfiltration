# 🛡️ Suspected Data Exfiltration from a PIP’d Employee  
**Tooling:** Microsoft Defender for Endpoint (Advanced Hunting)

---

## 📌 Scenario Overview

This scenario simulates a **suspected insider threat** involving an employee placed on a **Performance Improvement Plan (PIP)**. Following a behavioral incident, management raised concerns that the employee may attempt to **archive and exfiltrate sensitive company data** prior to leaving the organization.

The goal of this investigation was to determine whether any **user-driven archive or data exfiltration activity** occurred on the employee’s corporate endpoint using **Microsoft Defender for Endpoint (MDE) Advanced Hunting**.

---

## 🎯 Objectives

- Identify archive or compression activity on the endpoint
- Determine whether the activity was **user-driven or system-generated**
- Correlate file, process, and network telemetry
- Identify any evidence of data exfiltration
- Document findings and recommend improvements

---

## 🧪 Environment

- **Platform:** Microsoft Azure Virtual Machine  
- **Endpoint Name:** `windows-target-1`  
- **Security Tool:** Microsoft Defender for Endpoint  
- **Advanced Hunting Tables Used:**
  - `DeviceProcessEvents`
  - `DeviceFileEvents`
  - `DeviceNetworkEvents`

---

## 🧠 Hypothesis

> Because the employee had administrative access and no application restrictions, it was hypothesized that the employee may attempt to compress sensitive data using archive utilities (e.g., 7-Zip) and exfiltrate it from the corporate environment.

---

## 🔍 Investigation Methodology

The investigation followed a structured threat-hunting approach:

1. Identify potential archive activity
2. Correlate file creation events
3. Perform time-based process correlation
4. Analyze network activity for exfiltration
5. Validate findings and rule out false positives
6. Document results and propose improvements

---

## 🔎 Advanced Hunting Queries & Findings

---

### 1️⃣ Archive Utility Detection

**Purpose:**  
Identify execution of common archive and compression utilities that could be used to stage data for exfiltration.

```kql
let archive_applications = dynamic([
  "winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe",
  "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE",
  "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"
]);
DeviceProcessEvents
| where FileName has_any(archive_applications)
| order by Timestamp desc
