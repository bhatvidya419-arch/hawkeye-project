# hawkeye-project

# Comprehensive Analysis of the HawkEye Lab

**Lab Overview:** The HawkEye Lab simulates a real-world intrusion involving the HawkEye Reborn keylogger, a prevalent commodity malware used for credential theft and surveillance. The lab environment consists of a victim endpoint (Windows 10), an active directory server, a SIEM (ELK stack), and a simulated attacker C2 server. 

Below are the three perspectives from the Red, Blue, and Purple teams detailing the execution, detection, and collaborative analysis of this scenario.

---

# REPORT 1: Red Team Operation
**Objective:** Simulate an adversary deploying HawkEye Reborn to establish a foothold, steal credentials, and exfiltrate data, mimicking TTPs commonly associated with phishing campaigns and commodity malware operators.

## 1. Engagement Summary
The Red Team successfully compromised the target endpoint using a weaponized phishing payload disguised as a shipping invoice. The payload executed the HawkEye keylogger, established persistence, harvested system and user credentials, and exfiltrated the data to an attacker-controlled server via SMTP/HTTP.

## 2. Kill Chain Execution

### Phase 1: Initial Access (T1566.001 - Spearphishing Attachment)
*   **Action:** Crafted a malicious `.zip` archive containing a heavily obfuscated `.vbs` script, disguised as `Invoice_Q4_2023.pdf.vbs`.
*   **Execution:** The payload was delivered via a simulated phishing email. Upon execution, the VBS script performed base64 decoding and injected the HawkEye payload directly into memory (reflective PE injection) to bypass disk-based AV scans.

### Phase 2: Execution & Persistence (T1059.005, T1547.001)
*   **Action:** The VBS script spawned `powershell.exe` to execute the decoded binary.
*   **Persistence:** HawkEye created a registry RunKey (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsDefenderUpdater`) pointing to a dropped copy of the malware in `%AppData%\Roaming\Microsoft\Windows\`. 
*   **Defense Evasion:** The malware checked for known AV processes and modified the registry to lower macro security settings (`HKCU\Software\Microsoft\Office\16.0\Word\Security\VBAWarnings` = 1).

### Phase 3: Credential Access & Discovery (T1056.001, T1087)
*   **Action:** HawkEye initiated its keylogging module, hooking the keyboard buffer.
*   **Browser Credential Theft:** The malware utilized built-in routines to decrypt and extract saved credentials from Chromium-based browsers and Firefox.
*   **System Discovery:** Executed `systeminfo` and `whoami /all` via hidden `cmd.exe` windows to gather host enumeration data.

### Phase 4: Exfiltration (T1048.003 - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol)
*   **Action:** Instead of standard HTTP C2 beaconing, HawkEye packaged the stolen keylogs, clipboard data, and browser credentials into an encrypted `.zip` file.
*   **Exfiltration:** The archive was sent via SMTP (Port 587) to a Red Team controlled email address (`updates@redteam-c2.local`), blending in with legitimate email traffic.

## 3. Red Team Success Criteria
*   Initial execution bypassed signature-based AV.
*   Credentials were successfully harvested from the keylogger and browser stores.
*   Data reached the C2 SMTP server without being blocked by the firewall.

---
---

# REPORT 2: Blue Team Operation
**Objective:** Detect, contain, and investigate the HawkEye intrusion using available SIEM telemetry, EDR logs, and network traffic analysis.

## 1. Engagement Summary
The Blue Team successfully detected the HawkEye deployment during the exfiltration phase and traced the attack back to the initial phishing vector. The team developed custom SIEM correlation rules, contained the infected host, and performed host-based forensics to map the malware's footprint.

## 2. Detection & Analysis

### Detection 1: Suspicious Process Genealogy (EDR / Sysmon Event ID 1)
*   **Observation:** `wscript.exe` spawning `powershell.exe`, which in turn spawned `cmd.exe` to run `systeminfo`.
*   **Rule Logic:** Alert when `wscript.exe` or `cscript.exe` spawns `powershell.exe` with command-line arguments containing base64 strings.
*   **Severity:** High.

### Detection 2: Registry Persistence (Sysmon Event ID 13)
*   **Observation:** A registry value was added to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\` pointing to a binary in the user's `AppData` directory.
*   **Rule Logic:** Alert on any modification to Run keys where the file path is not a known, signed system binary.
*   **Severity:** Medium (Correlated to High when combined with Detection 1).

### Detection 3: Anomalous SMTP Traffic (Network Firewall / Zeek)
*   **Observation:** The victim endpoint initiated an outbound SMTP connection on port 587 to an unknown IP address, sending a high volume of data (the encrypted zip).
*   **Rule Logic:** Alert when an endpoint communicates with an external SMTP server that is not part of the corporate mail gateway list.
*   **Severity:** Critical.

## 3. Incident Response & Forensics
1.  **Containment:** The affected host (`WKSTN-04`) was immediately isolated from the network via EDR network containment.
2.  **Memory Acquisition:** Volatility was used to dump RAM. YARA rules identified the HawkEye Reborn payload injected into the `powershell.exe` process.
3.  **Disk Forensics:** 
    *   Recovered the malicious VBS from the user's `Downloads` folder.
    *   Identified the dropped payload in `%AppData%\Roaming\Microsoft\Windows\svhost.exe` (note the typo mimicking `svchost`).
    *   Extracted the SMTP credentials and C2 email address from the binary's strings.
4.  **Remediation:** 
    *   Removed the registry RunKey.
    *   Reset all passwords for the compromised user, as well as any credentials stored in the user's browser.
    *   Blocked the destination C2 IP and domain at the perimeter firewall.

## 4. Blue Team Success Criteria
*   Alert generated and triaged within 15 minutes of exfiltration.
*   Host isolated before lateral movement could occur.
*   Full attack timeline reconstructed for the Purple Team review.

---
---

# REPORT 3: Purple Team Handover Report
**Objective:** Synchronize Red and Blue Team findings to evaluate detection coverage, map the attack to MITRE ATT&CK, and prioritize defensive improvements.

## 1. Executive Summary
The Purple Team exercise successfully validated the Red Team's simulated HawkEye campaign and the Blue Team's detection capabilities. While the Blue Team successfully caught the exfiltration and persistence phases, there were notable gaps in detecting the initial execution and credential harvesting phases. This report outlines the combined timeline, coverage analysis, and actionable recommendations.

## 2. Combined Attack & Detection Timeline

| Time (UTC) | Red Team Action | Blue Team Detection | MITRE ATT&CK Technique | Detection Gap? |
| :--- | :--- | :--- | :--- | :--- |
| 10:00:05 | User executes `Invoice.pdf.vbs` | None | T1566.001 | **Yes:** Email gateway failed to scan VBS within ZIP. |
| 10:00:06 | VBS decodes payload, spawns PS | Alert 1: Suspicious Process Genealogy | T1059.001 | No: EDR caught the parent-child anomaly. |
| 10:00:08 | Payload injected into memory | None | T1055.001 | **Yes:** AMSI/EDR did not flag reflective injection. |
| 10:00:10 | Registry RunKey modified | Alert 2: Registry Persistence | T1547.001 | No: Sysmon Event 13 triggered correctly. |
| 10:05:12 | Browser credentials extracted | None | T1555.003 | **Yes:** No telemetry on local credential access. |
| 10:15:00 | SMTP exfiltration of data | Alert 3: Anomalous SMTP Traffic | T1048.003 | No: Zeek network monitoring caught the anomaly. |

## 3. Gap Analysis

### Gap 1: Initial Access / Email Gateway Bypass
*   **Finding:** The Red Team's ZIP/VBS payload bypassed the email gateway's static signature scanning.
*   **Impact:** The malware reached the user's inbox, relying entirely on user awareness to fail.
*   **Recommendation:** Implement aggressive file-type blocking on the email gateway (block `.vbs`, `.js`, `.lnk` inside archives). Deploy sandbox detonation for all unknown attachments.

### Gap 2: Defense Evasion / Process Injection
*   **Finding:** The reflective PE injection into `powershell.exe` was not flagged by the endpoint AV, though the anomalous parent-child process was flagged.
*   **Impact:** The malware ran uninhibited in memory, allowing credential harvesting.
*   **Recommendation:** Ensure AMSI (Antimalware Scan Interface) is enabled and integrated with the EDR. Create custom EDR rules to monitor for unusual memory allocations within PowerShell processes.

### Gap 3: Credential Access / Browser Stealing
*   **Finding:** The Blue Team had no visibility when HawkEye accessed the browser's `Login Data` SQLite database to extract saved passwords.
*   **Impact:** Credentials were compromised silently.
*   **Recommendation:** Implement Sysmon Event ID 11 (File Creation) and Event ID 10 (Process Access) rules to alert on non-browser processes accessing browser data directories (e.g., `*Chrome\User Data\Default\Login Data*`).

## 4. Strategic Recommendations & Next Steps

1.  **SIEM Rule Tuning (Blue Team):** Update the existing "Anomalous SMTP Traffic" rule to include a correlation logic: *If a host generates an SMTP alert, automatically check if that host triggered a "Suspicious Process Genealogy" alert in the previous 30 minutes. If yes, escalate to Critical severity automatically.*
2.  **Email Security Posture (IT Operations):** Deploy a phishing simulation campaign specifically targeting users with invoice-themed VBS payloads to measure user susceptibility, as technical controls failed at the gateway.
3.  **Endpoint Hardening:** Disable VBScript execution via Group Policy (`Turn off Windows Script Host`). Most modern enterprises do not require VBS for legitimate daily operations, rendering this attack vector useless.

## 5. Conclusion
The HawkEye lab demonstrated a classic commodity malware intrusion. The collaboration between Red and Blue teams highlighted that while network-based detections (exfiltration) and host persistence detections were robust, the endpoint lacked depth in catching memory injection and local credential theft. Implementing the recommended AMSI configurations, Sysmon file-access rules, and gateway hardening will significantly reduce the mean-time-to-detect (MTTD) for similar commodity malware families.
