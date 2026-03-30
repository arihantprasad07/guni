# Outbound Material

Use these messages when reaching out to early prospects such as agentic-browser teams, browser automation startups, or internal AI platform teams.

## Short cold DM

Hi {{name}} — I built Guni, a security layer for browser agents. It scans the page before the agent executes and blocks prompt injection, phishing forms, deceptive UI, and goal hijacking. If you are open, I would love to show a short pilot tailored to one of your browser workflows.

## Cold email

Subject: protecting browser agents from hostile pages

Hi {{name}},

I have been following what your team is building around browser automation and agentic workflows.

We built Guni because browser agents are exposed to prompt injection, phishing, deceptive UI, and goal hijacking directly inside the DOM. Guni sits between the page and the action layer and returns an `ALLOW`, `CONFIRM`, or `BLOCK` decision before the agent clicks.

We can run a short paid pilot on one high-risk workflow and show:

- what gets blocked
- what needs tuning
- what the latency impact looks like

Useful links:

- Live dashboard: `/dashboard`
- Enterprise page: `/enterprise`
- Security architecture: `/security`
- Pilot page: `/pilot`

Best,
{{your_name}}

## Discovery questions

- Which browser workflows are highest-risk today?
- Are you self-hosting or using a managed browser layer?
- Where would a malicious page do the most damage: auth, payments, admin, or data extraction?
- Do you want a hosted pilot first or a self-hosted evaluation?
