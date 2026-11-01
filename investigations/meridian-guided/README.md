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
Guided hunt completed. Investigation report pending.

## Training Context
The scenario details above come from the supplied briefing. My investigation write-up will separately describe the evidence reviewed, findings, and assistance used.
