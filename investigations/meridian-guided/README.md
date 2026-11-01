# Meridian — Hunt 25 (Guided)

Completed as a guided exercise in the LogNPacific cyber range.

## Overview
This project documents my completed Meridian guided threat hunt, involving a simulated intrusion into a healthcare web portal.

## Scenario Briefing
The supplied scenario centers on a single Ubuntu 22.04 host running Apache, a PHP web application, and a MySQL patient database.

An active defensive suite monitors endpoint, network, web, SSH, database, and command activity. Automated incident-response sweeps also modify parts of the environment. The assignment was to distinguish attacker activity from defensive actions and provisioning-related noise.

An additional challenge was determining which suspicious changes were detected and removed, and which were logged but left in place.

## Investigation Scope
- Platform: Azure Log Analytics
- Query language: Kusto Query Language (KQL)
- Environment: Ubuntu 22.04, Apache, PHP, and MySQL
- Scenario incident date: February 6, 2026

## Timestamp Handling
The briefing specifies EventTime_t as the actual event timestamp. TimeGenerated reflects ingestion time and is unsuitable for reconstructing this scenario.

Queries must exclude rows without EventTime_t and use EventTime_t for time filtering and chronological ordering.

## Status
Guided hunt completed. Investigation report available below.

## Training Context
The scenario details above come from the supplied briefing. My investigation write-up will separately describe the evidence reviewed, findings, and assistance used.

## Completion Results
- Version: Meridian (Guided)
- Flags completed: 16/16
- Investigation sections completed: 9/9
- Completion date: October 11, 2026


## Guided Exercise Queries
The following queries are adapted from the guided exercise material. Each example explains its purpose and the finding it helps investigate. Revised examples use EventTime_t for scenario timestamps and exclude rows without a valid event time.


| Investigation step | Table |
|---|---|
| Identify reconnaissance tools | MeridianAccess_CL |
| Investigate sensitive file reads | MeridianAccess_CL |
| Review successful SSH access | MeridianAuth_CL |
| Identify root-shell execution | MeridianAudit_CL |
| Inspect the surviving backdoor | MeridianSnapshot_CL |
| Examine blocked outbound connections | MeridianDefender_CL |
| Review memory acquisition | MeridianAudit_CL |


### 1. Identify reconnaissance tools

This query groups requests by user agent and sorts them by their first appearance.

```kusto
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where EventTime_t >= datetime(2026-02-06)
    and EventTime_t < datetime(2026-02-07)
| where ClientIp_s == "10.1.134.57"
| summarize FirstSeen=min(EventTime_t), Requests=count() by UserAgent_s
| order by FirstSeen asc
```

**Exercise finding:** The reconnaissance sequence was nmap, curl, whatweb, and gobuster. User-agent strings provide clues about tools but can be changed or spoofed.

### 2. Investigate sensitive file reads

This query finds successful responses from the vulnerable endpoint when a file parameter was supplied.

```kusto
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where EventTime_t >= datetime(2026-02-06)
    and EventTime_t < datetime(2026-02-07)
| where ClientIp_s == "10.1.134.57"
| where RequestUri_s has "config_viewer"
    and RequestUri_s contains "file="
| where StatusCode_s == "200"
| project EventTime_t, RequestUri_s, ResponseSize_s
| order by EventTime_t asc
```

**Exercise finding:** The attacker read /etc/passwd, followed by database.conf. The requests and response sizes helped establish the sequence; a successful HTTP status alone does not establish the exact response contents.

### 3. Review successful SSH access

This query checks accepted password logins shortly after the configuration file was accessed.

```kusto
MeridianAuth_CL
| where isnotempty(EventTime_t)
| where EventTime_t between
    (datetime(2026-02-06 04:08:00) .. datetime(2026-02-06 04:12:00))
| where RawMessage_s has "Accepted password"
| project EventTime_t, RawMessage_s
| order by EventTime_t asc
```

**Exercise finding:** svc_backup logged in from 10.1.134.57 at 04:09:31 UTC, 57 seconds after the configuration-file read. This timing supports suspected credential reuse, although the exact password is not available in the supplied evidence.

### 4. Identify root-shell execution

This query locates audit records involving the rootbash executable and displays the recorded user identifiers.

```kusto
MeridianAudit_CL
| where isnotempty(EventTime_t)
| where EventTime_t >= datetime(2026-02-06)
    and EventTime_t < datetime(2026-02-07)
| where Types_s has "EXECVE"
| where Argv_s has "rootbash"
| project EventTime_t, comm_s, exe_s, Argv_s, auid_s, euid_s
| order by EventTime_t asc
```

**Exercise finding:** /tmp/rootbash -p ran at 04:40:15 UTC with effective UID 0. This supported root-level execution. The available records did not establish how the binary was originally placed on disk.

### 5. Inspect the surviving backdoor

This query examines process snapshots containing the suspected backdoor executable.

```kusto
MeridianSnapshot_CL
| where isnotempty(EventTime_t)
| where EventTime_t >= datetime(2026-02-06)
    and EventTime_t < datetime(2026-02-07)
| where isnotempty(ProcBeaconExeLink_s)
| project EventTime_t, ProcBeaconName_s, ProcBeaconExeLink_s,
    ProcBeaconUid_s, ProcBeaconPPid_s, ProcBeaconPid_s
| order by EventTime_t asc
```

**Exercise finding:** /opt/meridian/scripts/health_check remained active as PID 267155. The exercise identified real UID 1001, effective UID 0, and parent PID 1. Comparing snapshots with sweep logs showed that detection had not resulted in removal.

### 6. Examine outbound connection detections

This query summarizes network records for the suspected command-and-control destination. The raw messages must be checked to distinguish blocked connections from other network events.

```kusto
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventTime_t >= datetime(2026-02-06)
    and EventTime_t < datetime(2026-02-07)
| where EventCategory_s == "NETWORK"
| where DestIp_s == "10.1.134.57"
| summarize Events=count(), FirstSeen=min(EventTime_t),
    LastSeen=max(EventTime_t) by DestIp_s, DestPort_s, RawMessage_s
| order by FirstSeen asc
```

**Exercise finding:** The guided investigation identified 73 blocked outbound connections to 10.1.134.57:43212. Blocking those connections did not prove that the backdoor process had stopped or been removed.

### 7. Review memory acquisition

This query identifies recorded AVML executions during the administrator's response.

```kusto
MeridianAudit_CL
| where isnotempty(EventTime_t)
| where EventTime_t > datetime(2026-02-06 05:25:00)
    and EventTime_t < datetime(2026-02-07)
| where Types_s has "EXECVE"
| where Argv_s has "avml" or comm_s has "avml"
| project EventTime_t, Argv_s, exe_s
| order by EventTime_t asc
```

**Exercise finding:** The administrator ran AVML twice, with the output path /tmp/evidence/memory.lime. Execution records document the acquisition commands; validating the resulting memory image would require examining the artifact.

### Key Lessons

- Use the scenario's event timestamp to reconstruct the timeline.
- Separate provisioning and defensive activity from attacker actions.
- Distinguish a detection from successful remediation.
- Compare network blocks with process evidence before declaring containment.
- Document evidence gaps instead of assuming missing details.



## Investigation Report
[Read the full report (PDF)](./Meridian_Cyber_Range_Incident_Report%20%282%29.pdf)
