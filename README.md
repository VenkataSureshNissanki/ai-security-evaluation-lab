# AI Security Evaluation & Automated Testing Lab

**65 automated penetration-style regression cases | Offline Python simulation | Synthetic data only**

An independent portfolio demonstration of an AI-agent security decision gateway. The test suite applies adversarial requests to a **mock policy evaluator**. It does not attack a live AI model, perform real penetration testing, open sockets, execute tools, or prove that a production agent is secure.

## What it tests

| Threat family | Examples |
|---|---|
| Prompt injection | Role spoofing, system-prompt extraction attempts, instruction override, percent/HTML/double encoding |
| Access control | Viewer/operator/admin privilege boundaries, disallowed tools, unknown roles |
| Human-in-the-loop | Approval tied to request ID, tenant, and action; stale/mismatched/boolean approval rejected |
| Data boundary | Cross-tenant reads and output tenant mismatch |
| Exfiltration / secrets | Simulated API-key, private-key, bearer-token exposure references |
| SSRF simulation | URL allowlisting, cloud metadata, loopback, credential-in-URL, non-HTTPS |
| Input attacks | Path traversal and SQL injection signatures |
| Robustness | Invalid types, missing IDs, oversized payload, multiple simultaneous policy violations |
| Safety invariants | Every decision has `tool_executed: false` — even when allowed |

## Run locally

Requires Python 3.11+ and no external packages:

```bash
python -m unittest discover -s tests -v
python scripts/run_demo.py
```

The unit test suite contains **65 individually named cases**, under `tests/test_demo.py`. The demo writes `demo_output/scenario_results.json` and `demo_output/summary.json`, which contain **synthetic decisions, not actual intrusion results**.

## Scope, evidence and honest limitations

- This is *rule-based simulation*, not a security assessment of a real LLM or deployed agent.
- Regexes and decoding are illustrative, not comprehensive protections against prompt injection or malicious input.
- URL allowlisting does not perform network I/O, DNS resolution, redirect validation, or IP pinning; production SSRF defense needs those controls.
- The simulation receives trusted role/tenant fields as direct input. Real systems must verify identity, authorization, tenant ownership, and approval provenance on the server.
- "Allowed" means *this local demonstration policy approved the request*, not that an external operation was performed.
- Model-based testing, security review, real systems, third-party APIs, exploit exploitation, and quantitative attack-success metrics are out of scope.

## CI

GitHub Actions runs the Python standard-library unit tests on pushes and pull requests. See the **Actions** tab for the actual CI run status. This project uses only fictional data and has no secrets, external service dependencies, or destructive operations.

For ethical use, test only systems you own or have explicit authorization to assess.
