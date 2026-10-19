# Discovery interview template

Forty minutes with a platform, security or infrastructure lead at a midmarket
SaaS or fintech-infrastructure company that lets an AI agent change
infrastructure, or is about to. The purpose is to find out whether the
protected-change problem is real for them and what they do about it today.
It is not a demo and nothing is pitched until the last five minutes.

Record answers verbatim where possible. A polite "that sounds useful" is a no.

## 1. What the agent does today (10 minutes)

- Which agents can change production, and through what: a CI token, a cloud
  role, a kubeconfig, a chat-ops bot?
- Walk me through the last change an agent made. Who knew before it happened?
- Has an agent ever made a change nobody asked for, or the right change to the
  wrong thing? What happened next?

## 2. How it is controlled today (10 minutes)

- What stops the agent doing something it should not? (Listen for: nothing,
  code review, a human in the loop, a policy engine, read-only access.)
- When a human approves, what exactly do they see, and how long does it take?
- If the approved change and the executed change differed, how would you know?
- After a timeout, how do you find out whether the change happened?

## 3. What it costs (10 minutes)

- How many engineer-hours went into the controls you have? Who maintains them?
- What did the last audit or customer security review ask about agents, and
  what did you answer?
- What would have to be true for you to let agents do more than they do now?

## 4. Fit and buying (5 minutes)

- Who would own this: platform, security, or nobody yet?
- What is already in the path that anything new must work with (identity
  provider, gateway, admission controller, SIEM)?
- What did you last buy in this area, from whom, and how long did it take?

## 5. Close (5 minutes)

- Describe the first workflow in two sentences. Ask: is this your problem, and
  would you run a three-week pilot on one namespace? Record the exact reply.

## After the call

| Field | Value |
|---|---|
| Company, role, date | |
| Agents that can change production today | |
| Current control, in their words | |
| Worst incident or near miss | |
| Would pilot: yes / no / not now, and the reason given | |
| Existing tools the pilot must integrate with | |
| What they said that contradicts our assumptions | |

Ten interviews before changing the first workflow. The last row is the one to
read first.
