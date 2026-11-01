# Operation ECHOLEAK

Completed in the LogNPacific cyber range, with assistance developing queries and interpreting results.


## Overview
This write-up documents my Operation ECHOLEAK investigation
completed as part of LogNPacific cyber-range training.

## Scenario Briefing
The supplied scenario takes place at Cormorant Capital Partners, a simulated financial advisory firm using Microsoft 365 Copilot.

An alert flagged five previously unopened sensitive files accessed by financial analyst Emily Chen within six seconds. She reported asking Copilot only to summarize a quarterly report received by email approximately ninety minutes earlier. No unusual sign-ins were reported during the investigation window.

The assignment was to determine why Copilot accessed unrelated files, trace the activity between the email and the file-access burst, and assess whether data left the organization. The exercise models indirect prompt injection associated with CVE-2025-32711.

## Investigation Scope
- Workspace: LAW-HuntPractice
- Scenario window: September 20, 2026, 09:00–11:00 UTC
- Identities: emily.chen@cormorantcapital.com and mark.ross@cormorantcapital.com
- Tables:
  - OfficeActivity_CL — Microsoft 365 unified audit logs
  - CopilotAudit_CL — Copilot interaction audit logs
  - EntraSignIn_CL — Microsoft Entra ID sign-in logs


These details summarize the supplied briefing. The linked investigation report describes my findings and the limitations of the available evidence.


## Status
Investigation report completed and available below.

## Completion Results

- Flags completed: 17/17
- Investigation sections completed: 6/6
- Completion date: October 21, 2026
- Platform: LogNPacific cyber range
- Workspace: LAW-HuntPractice

## Investigation Queries and Findings

These examples are adapted from the platform's verification queries, with chronological sorting and investigation-window filters added where appropriate. Findings summarize the completed exercise. These adapted examples have not been rerun against the workspace.

All queries filter on RunId to separate this scenario from other workspace data. This exercise uses TimeGenerated for event timing.

### 1. Identify the delivery email

This query reviews email delivery events for Emily before the suspicious Copilot activity.

```kusto
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "MessageReceived"
    and OfficeWorkload == "Exchange"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T10:00:00Z))
| project TimeGenerated, SenderAddress, Subject, AttachmentNames
| order by TimeGenerated asc
```

**Exercise finding:** The email came from quarterly.reports@globalfinancereview.net and carried Q3-2026-Global-Markets-Review.docx.

### 2. Trace the legitimate prompt and subsequent tool calls

This query places the user's request and Copilot's subsequent actions into chronological order.

```kusto
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between
    (datetime(2026-09-20T10:42:00Z) .. datetime(2026-09-20T10:44:00Z))
| project TimeGenerated, InteractionType, UserPrompt,
    ToolName, ToolParameters
| order by TimeGenerated asc
```

**Exercise finding:** Emily requested a summary of the quarterly report. Copilot subsequently searched for confidential board minutes, acquisition targets, and salary information, then read unrelated sensitive documents.

The mismatch between the requested task and the tool activity supported the indirect prompt-injection assessment.

### 3. Examine the initial file-access burst

This query lists unrelated files accessed during the initial collection window, excluding the quarterly report.

```kusto
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where TimeGenerated between
    (datetime(2026-09-20T10:42:35Z) .. datetime(2026-09-20T10:43:15Z))
| where OfficeObjectId !has "Q3-2026"
| project TimeGenerated, OfficeObjectId
| order by TimeGenerated asc
```

**Exercise finding:** Five sensitive files were accessed in approximately six seconds. They included board materials, an M&A assessment, salary information, a client portfolio, and Copilot configuration.

This query establishes the access sequence. Establishing that these were first-time accesses also requires historical access records or the exercise's supplied context.

### 4. Inspect suspicious URLs in Copilot responses

This query retrieves responses containing the suspicious destination.

```kusto
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Response"
| where TimeGenerated between
    (datetime(2026-09-20T09:00:00Z) .. datetime(2026-09-20T11:00:00Z))
| where CopilotResponse contains "metrics-cdn.analyticshub.io"
| project TimeGenerated, UserId, CopilotResponse
| order by TimeGenerated asc
```

**Exercise finding:** Copilot responses contained Markdown image URLs pointing to metrics-cdn.analyticshub.io, with encoded information in URL parameters.

Fetching those image URLs could transmit information to the external destination. Response text alone does not prove that a request completed or establish the exact data received by the external server.

### 5. Review the later search phase

This query examines searches after the initial collection phase.

```kusto
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Search"
| where TimeGenerated > datetime(2026-09-20T10:44:00Z)
    and TimeGenerated <= datetime(2026-09-20T11:00:00Z)
| project TimeGenerated, ToolParameters
| order by TimeGenerated asc
```

**Exercise finding:** Later searches targeted confidential, restricted, board, acquisition, and salary information. The completed exercise identified eight additional sensitive files accessed during this phase.

Search events show the requested searches; corresponding file-access events establish which documents were accessed.

### 6. Assess total file-access scope

This query counts distinct file identifiers across both collection phases.

```kusto
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where TimeGenerated between
    (datetime(2026-09-20T10:42:35Z) .. datetime(2026-09-20T10:47:00Z))
| where OfficeObjectId !has "Q3-2026"
| distinct OfficeObjectId
| summarize SensitiveFilesAccessed=count()
```

**Exercise finding:** The exercise established 13 sensitive files accessed: five initially and eight during the later search phase. Access does not, by itself, prove that the complete contents of every file were exfiltrated.

### 7. Review authentication evidence

This query checks Emily's sign-in records around the incident.

```kusto
EntraSignIn_CL
| where RunId == "el--17-20260920"
| where UserPrincipalName =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated between
    (datetime(2026-09-20T08:00:00Z) .. datetime(2026-09-20T12:00:00Z))
| project TimeGenerated, IPAddress, Location, Status,
    ConditionalAccessStatus, AppDisplayName
| order by TimeGenerated asc
```

**Exercise finding:** The supplied authentication evidence showed Emily's expected sign-in pattern without reported anomalies. Combined with the document-to-Copilot sequence, this supported external input manipulation rather than an account-compromise explanation.

An absence of anomalous sign-ins alone cannot conclusively rule out every form of account compromise.

## Assessment and Evidence Limitations

The completed exercise supported indirect prompt injection through external document content. Copilot used legitimate capabilities to perform actions outside the user's requested summary.

The investigation identified sensitive file access, suspicious external image URLs, and exposure of system-prompt or configuration information. The available logs did not establish the complete contents of every accessed file or precisely what reached the external destination.

## Key Lessons

- Correlate email delivery, Copilot interactions, file access, and sign-in evidence.
- Compare the user's request with the actions performed by the AI assistant.
- Evaluate suspicious behavior against the baseline supplied in the exercise.
- Distinguish file access, attempted transmission, and confirmed data receipt.
- Document visibility limitations rather than filling gaps with assumptions.

## Investigation Report


[Read the full report (PDF)](./Operation_ECHOLEAK_Final_Report%20%281%29.pdf)
