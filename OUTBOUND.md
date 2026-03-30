# Outbound Material

Use these notes for targeted outreach to agentic-browser teams, browser automation startups, and internal AI platform groups.

## Short cold DM

Hi {{name}} - I built Guni, a security layer for browser agents. It evaluates the page before execution and helps block prompt injection, phishing forms, deceptive UI, and goal hijacking. If useful, I can share a short workflow-specific evaluation.

## Cold email

Subject: browser-agent security evaluation

Hi {{name}},

I have been following your work on browser automation and agentic workflows.

Guni sits between the page and the action layer. It evaluates the DOM before execution and returns an `ALLOW`, `CONFIRM`, or `BLOCK` decision with evidence. That helps teams reduce prompt injection, phishing, redirect abuse, deceptive UI, and goal hijacking risk in live browser flows.

If helpful, we can run a focused evaluation on one higher-risk workflow and share:

- blocked or flagged scenarios
- evidence returned by the policy layer
- latency and rollout observations

Useful links:

- Live dashboard: `/dashboard`
- Enterprise page: `/enterprise`
- Security architecture: `/security`
- Evaluation page: `/pilot`

Best,
{{your_name}}

## Discovery questions

- Which browser workflows are highest-risk today?
- Are you self-hosting or using a managed browser layer?
- Where would a malicious page do the most damage: auth, payments, admin, or data extraction?
- Do you want a hosted evaluation or a self-hosted review?
