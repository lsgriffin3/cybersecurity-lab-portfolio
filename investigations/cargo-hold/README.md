
# Cargo Hold — Hunt 19
Training context: This report documents a simulated LogNPacific cyber-range exercise completed with guided assistance.


## Overview
This project documents my completed Cargo Hold threat-hunting exercise in the LogNPacific cyber range.

## Scenario Briefing
Cargo Hold is the second exercise in the Azuki saga. The supplied scenario describes an attacker returning through a previously compromised account, accessing azuki-sl through RDP, and moving laterally to azuki-fileserver01 as fileadmin.

The briefing describes two phases: discovery, file staging, and uploads to file.io; followed by persistence, credential dumping, and removal of logs and PowerShell history.

## Investigation Scope
The assignment was to trace the return visit using Microsoft Defender for Endpoint telemetry in LAW-Cyber-Range:

- DeviceLogonEvents
- DeviceProcessEvents
- DeviceFileEvents
- DeviceNetworkEvents

The investigation focused on azuki-sl and azuki-fileserver01 (10.1.0.188).

These details summarize the supplied briefing. My investigation report will separately describe the evidence I reviewed and the findings I verified.


Hunt completed. Investigation report available below.

## Completion Results

- Flags completed: 21/21
- Investigation sections completed: 9/9
- Completion date: October 17, 2026
- Platform: LogNPacific cyber range
- Workspace: LAW-Cyber-Range

## Investigation Queries and Findings

These KQL examples are adapted from the completed exercise's verification material. Time filters and selected output fields have been added for clarity. They document the investigation method and are not presented as an exact history of the queries I ran. These revised examples have not been rerun against the workspace.

This scenario uses Timestamp to reconstruct activity on November 22, 2025.

### 1. Identify the returning account's source address

This query reviews remote interactive logons for the previously compromised account.

```kusto
DeviceLogonEvents
| where DeviceName =~ "azuki-sl"
| where AccountName =~ "kenji.sato"
| where LogonType =~ "RemoteInteractive"
| where Timestamp between
    (datetime(2025-11-22T00:00:00Z) .. datetime(2025-11-22T01:00:00Z))
| project Timestamp, AccountName, RemoteIP, ActionType, LogonType
| order by Timestamp asc
```

**Exercise finding:** The account returned from `159.26.106.98` at 00:27:58 UTC. The exercise identified a successful logon without a preceding brute-force burst in the reviewed window. An absence of failed logons alone does not establish how the credentials were obtained.

### 2. Trace lateral movement to the file server

This query identifies the remote desktop client launched on the workstation.

```kusto
DeviceProcessEvents
| where DeviceName =~ "azuki-sl"
| where FileName =~ "mstsc.exe"
| where Timestamp between
    (datetime(2025-11-22T00:27:53Z) .. datetime(2025-11-22T00:45:00Z))
| project Timestamp, AccountName, ProcessCommandLine
| order by Timestamp asc
```

The following query checks the corresponding file-server logons.

```kusto
DeviceLogonEvents
| where DeviceName =~ "azuki-fileserver01"
| where RemoteIP == "10.1.0.204"
| where Timestamp between
    (datetime(2025-11-22T00:38:45Z) .. datetime(2025-11-22T00:39:00Z))
| project Timestamp, AccountName, LogonType, RemoteIP, ActionType
| order by Timestamp asc
```

**Exercise finding:** `mstsc.exe /V:10.1.0.188` ran at 00:38:47 UTC. On `azuki-fileserver01`, the `fileadmin` account recorded a Network logon at 00:38:49 and an Unlock event at 00:38:57. Correlating the source process with destination logons supported the lateral-movement timeline.

### 3. Review discovery commands

This query collects share, identity, privilege, and network discovery activity.

```kusto
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where AccountName =~ "fileadmin"
| where Timestamp between
    (datetime(2025-11-22T00:38:00Z) .. datetime(2025-11-22T00:44:00Z))
| where FileName in~ ("net.exe", "net1.exe", "whoami.exe", "ipconfig.exe")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Exercise findings:**

- `net share` at 00:40:54 UTC.
- `net view \\10.1.0.188` at 00:42:01 UTC.
- `whoami /all` at 00:42:24 UTC.
- `ipconfig /all` at 00:42:46 UTC.

These commands established what the account could access and how the host was configured. Their significance came from their timing and surrounding activity; each command can also have legitimate administrative uses.

### 4. Investigate hidden staging and script retrieval

This query reviews commands used to conceal the staging directory and retrieve a script.

```kusto
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where Timestamp between
    (datetime(2025-11-22T00:50:00Z) .. datetime(2025-11-22T01:05:00Z))
| where FileName in~ ("attrib.exe", "certutil.exe")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

This query checks the associated network connection results.

```kusto
DeviceNetworkEvents
| where DeviceName =~ "azuki-fileserver01"
| where Timestamp between
    (datetime(2025-11-22T00:50:00Z) .. datetime(2025-11-22T01:05:00Z))
| where RemoteIP == "78.141.196.6"
| project Timestamp, RemoteIP, RemotePort, ActionType
| order by Timestamp asc
```

**Exercise finding:** The command `attrib +h +s C:\Windows\Logs\CBS` concealed the staging directory. Two connections to port 7331 failed before a connection to port 8080 succeeded at approximately 01:02:59 UTC. The associated certutil command targeted `ex.ps1` in the staging directory.

A successful connection supports network reachability. File creation or content evidence would provide stronger confirmation of the downloaded artifact.

### 5. Examine collection and archive preparation

This query reviews copying and compression commands.

```kusto
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where Timestamp between
    (datetime(2025-11-22T01:00:00Z) .. datetime(2025-11-22T01:50:00Z))
| where FileName in~ ("xcopy.exe", "tar.exe")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

The following query checks the credential file identified in the staged data.

```kusto
DeviceFileEvents
| where DeviceName =~ "azuki-fileserver01"
| where Timestamp between
    (datetime(2025-11-22T01:00:00Z) .. datetime(2025-11-22T01:50:00Z))
| where FileName =~ "IT-Admin-Passwords.csv"
| project Timestamp, FileName, FolderPath, ActionType
| order by Timestamp asc
```

**Exercise finding:** Four `xcopy` commands collected department folders using `/E /I /H /Y`. The staged IT-Admin folder contained `IT-Admin-Passwords.csv`.

Three recorded tar commands created `financial.tar.gz`, `credentials.tar.gz`, and `shipping.tar.gz`. A fourth archive, `contracts.zip`, appeared later in the upload commands, but the supplied process evidence did not establish which process created it. I did not assume it was created by tar or PowerShell.

### 6. Review outbound upload commands

This query identifies upload commands directed at the file-sharing service.

```kusto
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where Timestamp between
    (datetime(2025-11-22T01:55:00Z) .. datetime(2025-11-22T02:05:00Z))
| where FileName =~ "curl.exe"
| where ProcessCommandLine has "file.io"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```

**Exercise finding:** Four curl upload commands ran between 01:59:54 and 02:00:20 UTC, targeting `credentials.tar.gz`, `financial.tar.gz`, `contracts.zip`, and `shipping.tar.gz`.

The exercise classified this activity as exfiltration. Process command lines show the upload instructions; confirming successful receipt and exact transferred contents would require supporting network, response, or destination evidence.

### 7. Identify persistence and credential-dumping activity

This query reviews the registry modification and renamed dumping utility.

```kusto
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where Timestamp between
    (datetime(2025-11-22T02:05:00Z) .. datetime(2025-11-22T02:30:00Z))
| where FileName in~ ("reg.exe", "pd.exe")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Exercise finding:** At 02:10:50 UTC, a registry command configured the `FileShareSync` Run-key value to launch `C:\Windows\System32\svchost.ps1` through hidden PowerShell.

At 02:24:44 UTC, `pd.exe` ran with arguments targeting PID 876 and output path `C:\Windows\Logs\CBS\lsass.dmp`. The exercise identified the utility as renamed ProcDump and the target as LSASS. The command documents the dumping attempt; dump-file evidence would help confirm successful acquisition.

### 8. Reconstruct evidence-removal activity

This query reviews event-log clearing commands.

```kusto
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where Timestamp between
    (datetime(2025-11-22T02:24:00Z) .. datetime(2025-11-22T02:27:00Z))
| where FileName =~ "wevtutil.exe"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```

The following query checks deletion of persistent PowerShell command history.

```kusto
DeviceFileEvents
| where DeviceName =~ "azuki-fileserver01"
| where Timestamp between
    (datetime(2025-11-22T02:24:00Z) .. datetime(2025-11-22T02:27:00Z))
| where FolderPath contains "PSReadLine"
| where FileName =~ "ConsoleHost_history.txt"
| where ActionType =~ "FileDeleted"
| project Timestamp, FileName, FolderPath, ActionType
| order by Timestamp asc
```

**Exercise finding:** Six event-log clearing commands ran in rapid succession, beginning with Security at 02:25:49.044 UTC. The PowerShell history file `ConsoleHost_history.txt` was deleted at 02:26:01 UTC.

The retained endpoint telemetry allowed the cleanup sequence to be reconstructed despite the attempted removal of local evidence.

## Key Lessons

- Correlate workstation processes with destination-host logons.
- Investigate legitimate administrative tools in the context of the full activity sequence.
- Check process evidence before assuming which copying or compression tool was used.
- Separate command execution from confirmed file creation or successful data transfer.
- Treat plaintext credential files on shared storage as a serious exposure.
- Preserve centralized telemetry because local logs and command history can be removed.
- Document evidence gaps rather than filling them with assumptions.



## Investigation Report

[Read the full report (PDF)](../Cargo_Hold_Threat_Hunt_Final_Report%20%281%29.pdf)
