# Sentinel SOC 7-Day AI Agent Security Pilot

Sentinel SOC is a software-delivered AI security analyst for AI agents.

## Who This Is For

- AI startups
- Developer tool teams
- Teams building AI agents that call tools, APIs, files, databases, or wallets
- Teams worried about prompt injection, tool misuse, and data exfiltration

## What Sentinel Monitors

- Prompts
- Tool calls
- File access
- API calls
- Database queries
- Wallet/payment actions
- Autonomous decisions

## What Sentinel Detects

- Prompt injection
- System prompt extraction
- Sensitive file access
- Data exfiltration attempts
- Unsafe tool use
- Unauthorized database access
- Suspicious outbound requests
- Risky wallet/payment actions

## Pilot Scope

- 7 days
- 1-3 AI agents
- SDK/API integration
- Founder-assisted onboarding
- Observe Mode first, Protect Mode optional for selected high-risk tools

## Observe Mode vs Protect Mode

### Observe Mode

- Current pilot mode
- Agent actions are logged to Sentinel
- Sentinel detects risky behavior
- Sentinel creates incidents
- Sentinel investigates and generates reports
- Sentinel recommends response actions
- Best for early pilots because it is safe and easy to integrate

### Protect Mode

- Next enforcement mode
- Agent asks Sentinel before executing high-risk tool calls
- Sentinel returns `allow`, `warn`, `require_approval`, or `block`
- Useful for sensitive resources like:
  - `.env`
  - Databases
  - Customer records
  - Payment/wallet actions
  - Outbound HTTP requests
  - Code execution tools

Sentinel starts in Observe Mode for pilot safety. For teams that want stronger protection, we can enable Protect Mode for selected high-risk tools after approval.

## Deliverables

- Live incident monitoring
- Generated incident reports
- Critical-risk summaries
- Recommended response actions
- Guardrail recommendations
- Final founder-led security review

## What Is Automated

- Event ingestion
- Detection
- Supervisor triage
- Report generation
- Recommended remediation

## What Is Founder-Assisted

- Onboarding
- Rule tuning
- Incident review
- Final recommendations

## Current MVP Limitations

- Remediation is suggested/human-approved
- Enterprise RBAC/SSO is not included yet
- Persistence may be local/in-memory unless deployment is configured
- Sentinel SOC is not a replacement for a full SOC yet
