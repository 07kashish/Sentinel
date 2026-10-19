# YC Application Notes

## One-Line Company Description

Sentinel SOC is a software-delivered AI security analyst that protects AI agents from prompt injection, tool misuse, and unsafe autonomous actions.

## What We Built

- Live AI-agent runtime event ingestion
- Detection for prompt injection and sensitive file access
- CRITICAL incident creation
- Supervisor triage
- Incident report generation
- Remediation recommendation
- Python SDK/demo script
- Founder-assisted pilot docs

## Product Mode

- Observe Mode today
- Protect Mode next

## Target Customers

- AI startups
- Devtool companies
- Fintech/healthtech teams deploying agents
- Teams building agents with tool/API/database/file access

## Pilot Offer

7-day founder-assisted pilot for 1-3 agents.

## Demo Script Summary

An agent receives a malicious prompt, tries to access `.env`, Sentinel detects a critical incident, generates a report, and recommends response actions.

## Competitor Positioning

Sentinel is not another generic AI SOC.

Traditional AI SOC tools automate alerts from SIEM/EDR/cloud systems. Sentinel focuses on the AI-agent runtime layer: prompts, tool calls, file access, API calls, and autonomous decisions.

## Current Limitations

- Not enterprise production-ready yet
- Remediation is suggested/human-approved
- Full multi-tenant SaaS and persistence are next
- Early pilots are founder-assisted

## Next 30 Days

- Onboard 3 pilots
- Add persistence
- Add tenant separation
- Improve SDK integrations
- Add Protect Mode for selected tools
- Improve dashboard/reporting
