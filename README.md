# 🛡️ Suspected Data Exfiltration from PIP’d Employee

---

## 📌 Overview

This scenario simulates a **suspected insider threat** involving an employee placed on a Performance Improvement Plan (PIP). Management raised concerns that the employee may attempt to **archive and exfiltrate sensitive data** prior to leaving the organization.

The investigation was conducted using **Microsoft Defender for Endpoint (MDE) Advanced Hunting**, focusing on endpoint, process, file, and network telemetry.

---

## 🎯 Objectives

- Identify potential archive/compression activity
- Determine whether activity was **user-driven or system-generated**
- Correlate file, process, and network events
- Identify any evidence of data exfiltration
- Document findings and recommend improvements

---

## 🧪 Environment

- **Platform:** Microsoft Azure Virtual Machine  
- **Endpoint:** `windows-target-`  
- **Tooling:** Microsoft Defender for Endpoint (Advanced Hunting)  
- **Relevant Tables:**
  - `DeviceProcessEvents`
  - `DeviceFileEvents`
  - `DeviceNetworkEvents`

---

## 🧠 Hypothesis

> The employee may attempt to compress sensitive data using archive utilities (e.g., 7-Zip) and exfiltrate the data to an external location.

---

## 🔍 Investigation & Analysis

### 1️⃣ Archive Utility Detection

**Purpose:**  
Identify execution of common archive/compression utilities.

```kql
let archive_applications = dynamic([
  "winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe",
  "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE",
  "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"
]);
DeviceProcessEvents
| where FileName has_any(archive_applications)
| order by Timestamp desc
