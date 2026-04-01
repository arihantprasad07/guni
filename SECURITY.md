# Security And Trust

Guni is security middleware for browser agents and agentic web products. This document explains what is production-ready today, how data is handled, and what customers should expect when evaluating the product.

## What Guni does

Guni inspects page HTML before an agent executes on it.

It detects:

- prompt injection
- phishing forms
- deceptive UI
- malicious scripts
- goal hijacking
- clickjacking
- CSRF and token theft patterns
- redirect abuse

The result is a policy decision:

- `ALLOW`
- `CONFIRM`
- `BLOCK`

## Deployment model

Guni can be used in two ways:

### 1. Self-hosted

Customers run the SDK or API in their own environment and keep browser traffic and scan results within their infrastructure.

### 2. Managed API

Customers send HTML and agent-goal context to the hosted API. This is best for fast pilots and early deployments.

## Data handling

Current implementation may persist the following runtime state:

- scan audit logs
- waitlist entries
- filesystem-backed runtime events
- MongoDB app data for users, organizations, scans, alerts, billing, audit events, and custom rules

By default, local runtime state is stored in `.guni/` for development. In production, paths should be mapped to a dedicated writable volume via environment variables.

## Recommended production environment variables

- `GUNI_DATA_DIR`
- `GUNI_DB_PATH`
- `GUNI_LOG_PATH`
- `GUNI_KEYS_PATH`
- `GUNI_WAITLIST_PATH`
- `GUNI_EVENT_LOG_PATH`
- `GUNI_RATE_LIMIT`
- `GUNI_API_KEYS`
- `GUNI_LLM_API_KEY`
- `GUNI_LLM_PROVIDER`
- `GUNI_LLM_MODEL`
- `GUNI_LLM_BASE_URL`
- `GUNI_SESSION_SECRET`

## Buyer-facing security posture

What is strong today:

- deterministic in-process test coverage for core API routes
- explicit policy decisions with evidence
- self-hostable architecture
- isolated runtime state paths
- deployable FastAPI service with healthcheck

What is still maturing:

- formal external penetration testing
- SSO and enterprise identity integration
- tenant isolation beyond simple key-based separation
- role-based access control for portal/admin surfaces
- signed audit export and tamper-evident logging

## Recommended customer rollout

For serious customers, the best rollout is:

1. start with a pilot on one or two high-risk workflows
2. run attack simulations against staging or sandbox flows
3. measure block rate, false positives, and latency
4. expand to additional browser actions once trust is established

## Responsible disclosure

If you find a vulnerability, do not open a public issue with exploit details.

Email: `hello@guni.dev`

Include:

- affected route or module
- reproduction steps
- impact
- suggested fix if available
