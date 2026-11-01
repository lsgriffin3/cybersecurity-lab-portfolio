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



## Investigation Report


[Read the full report (PDF)](./Operation_ECHOLEAK_Final_Report%20%281%29.pdf)
