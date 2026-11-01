
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


## Investigation Report
[Read the full report (PDF)](./Cargo_Hold_Threat_Hunt_Final_Report.pdf)

