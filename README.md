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
- **Endpoint Name:** `windows-target-`  
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
````

**Finding:**
Archive-related activity was initially observed on the endpoint, triggering further investigation to determine whether the behavior was malicious or user-driven.

---

### 2️⃣ File Activity Correlation

**Purpose:**
Determine whether ZIP files were created during the timeframe of observed archive-related activity.

```kql
let specificTime = datetime(2024-10-15T19:00:48.5615171Z);
let VMName = "windows-target-";
DeviceFileEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Finding:**
ZIP files such as `vmagentlogs.zip` were created within the analyzed timeframe.

---

### 3️⃣ Process Correlation (±2 Minutes)

**Purpose:**
Determine whether the ZIP file creation was triggered by **user-initiated activity** or automated system processes.

```kql
let t = datetime(2024-10-15T19:00:48Z);
DeviceProcessEvents
| where DeviceName startswith "windows-target"
| where Timestamp between ((t - 2m) .. (t + 2m))
| where InitiatingProcessAccountName !in ("SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE")
| order by Timestamp desc
```

**Finding:**
No user-initiated processes were identified during the correlation window.
Observed activity was associated with Azure system components, including:

* `collectguestlogs.exe`
* `wpappagent.exe`

These processes are part of **normal Azure VM diagnostics and log collection**.

---

### 4️⃣ Network Activity Analysis

**Purpose:**
Identify any outbound network activity consistent with data exfiltration.

```kql
let t = datetime(2024-10-15T19:00:48Z);
DeviceNetworkEvents
| where DeviceName startswith "windows-target"
| where Timestamp between ((t - 2m) .. (t + 2m))
| order by Timestamp desc
```

**Finding:**
No suspicious or unauthorized outbound network connections were observed during the analyzed timeframe.
No evidence of data exfiltration was identified.

---

## 🕒 Timeline Summary and Findings

| Time (UTC)          | Observation                       | Interpretation            |
| ------------------- | --------------------------------- | ------------------------- |
| 2026-01-28 18:09:51 | Archive-related activity detected | Triggered investigation   |
| Same window         | `vmagentlogs.zip` created         | Azure diagnostic behavior |
| ±2 minutes          | Only system processes observed    | No user involvement       |
| ±2 minutes          | No outbound network activity      | No exfiltration           |

---

## 🧾 Final Conclusion

This threat hunting investigation analyzed file, process, and network activity related to suspected data exfiltration by a PIP’d employee. While archive-related activity was initially observed, further correlation analysis determined the behavior was **system-generated by Azure diagnostic processes** and **not associated with user-initiated actions**.

No evidence of data exfiltration or malicious insider activity was identified during the analyzed timeframe.

---

## 🔧 Improvement Opportunities

* Improve differentiation between system-generated and user-generated archive activity
* Exclude known Azure diagnostic processes in baseline threat hunts
* Implement alerting for abnormal archive creation patterns
* Enhance outbound network visibility for insider threat scenarios
* Apply stricter monitoring controls for users placed on PIPs

---

## 📚 Key Takeaways

* Not all archive activity is malicious
* Time-based correlation is critical in threat hunting
* Eliminating false positives is a successful hunt outcome
* Benign conclusions are valid and realistic in SOC investigations
* Clear documentation strengthens incident response maturity

---

## 🏁 Status

✅ Scenario Complete
✅ Benign Outcome Confirmed
✅ Suitable for Portfolio / GitHub / WGU Submission

```
