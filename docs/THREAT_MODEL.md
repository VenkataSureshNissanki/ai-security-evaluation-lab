# SentinelDesk Threat Model and Trust Boundaries

## Assets and actors

- **Assets:** tenant-specific customer tickets, internal knowledge articles, operator drafts, supervisor approvals, audit history, sandbox outbox.
- **Actors:** viewer, operator, administrator/supervisor; untrusted customer input and knowledge-base content; hypothetical attacker controlling a ticket or poisoned KB entry.
- **Objective:** prevent a malicious instruction embedded in lower-trust text from crossing the boundary into authorization, tool access, data disclosure, or outbound side effects.

## Core boundaries

1. **Identity:** principal is resolved server-side from the incoming demo key; API bodies cannot specify user identity or tenant.
2. **Data:** every ticket and document query is tenant-scoped at query time. A missing/foreign record returns 404.
3. **Instructions vs data:** customer messages and KB article bodies remain untrusted data; direct/indirect injection indicators can quarantine a draft. The deterministic draft builder doesn't interpret instructions from either source.
4. **Approval:** an administrator other than the draft creator must approve a specific draft. "Approved" cannot be asserted by a caller-supplied Boolean.
5. **Effect:** the only effectful action is an atomic write to a local sandbox outbox, with tenant-bound approval and one-delivery-per-draft constraint. Real email and HTTP calls are never attempted.
6. **Evidence:** audit logs capture action metadata only, never bearer keys or raw customer messages.

## Attack narratives & controls

| Threat story | Expected protection | Tests / observation |
|---|---|---|
| Attacker modifies ticket to direct agent to reveal its system prompt | Ticket screened; no draft produced | `AC-103`, prompt-injection tests |
| Attacker poisons internal FAQ retrieved by agent | KB is treated as untrusted and quarantined | `AC-105`, knowledge tests |
| Tenant A user accesses tenant B ticket or uses ID spoofing | Tenant filter in SQL enforced by server | Cross-tenant ticket and triage tests |
| Viewer attempts privilege escalation into drafting or approval | Permission checked on every endpoint | RBAC tests |
| Staff bypass supervisor gate with a truthy flag | Approval is a server-created database row, not a request field | Approval-before-send tests |
| Approval replay sends same reply twice | State transition and unique outbox row in `BEGIN IMMEDIATE` transaction | Repeat-send test |
| An external reference points at metadata service or localhost | Allowlisted HTTPS reference URL policy, no actual URL fetching | Reference URL tests |
| User tries malformed payloads or SQL syntax | Pydantic limits, parameterized SQL | Invalid-search tests |

## Residual risks / limitations (important)

- **Not production authentication.** Local seeded keys are known and deliberately public. No expiry/refresh, brute-force protection, secure session or enterprise identity provider. Run on localhost only.
- **Not true LLM agent execution.** The response composer is deterministic and no real model is called. A deployed model may behave differently.
- **Regex cannot guarantee prompt-injection resistance.** Encoded, multilingual, contextual and novel attacks may bypass screening. Structural non-interference matters more than text filters.
- **No true SSRF request execution.** The URL check illustrates deny by default. Production needs resolver/IP verification, redirect checks, DNS rebinding controls, egress restrictions, and network firewall policies.
- **Simplified tenant and permission architecture.** No per-ticket ABAC, tenant administration, identity federation, compliance posture, or formal authorization proof.
- **Local SQLite.** No distributed transactions, migration tool, centralized logging, backup encryption, rate limits, or scalable queue.
- **No secrets or real customer data.** Audit and report assertions only demonstrate behavior for the local synthetic fixtures.
- **Not a penetration test of a third-party application.** All tests run in the user's own local sandbox and are safe to rerun.

## Suggested next phase

Add a separately configured Ollama/local model with **proposed** tool intents as untrusted messages to the policy gateway; apply execution limits and capture tool-intent, refusal, exploit attempt, judge evidence, decision and audit chain. Add CI dashboards for attack-success rates against explicitly defined fixtures (do not confuse fixture passing with model security). External targets require written scope and authorization.