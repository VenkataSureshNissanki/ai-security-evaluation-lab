# Local Evidence — SentinelDesk

This file documents locally executed regression evidence at the time of the project upgrade.

**Command:** `python -m pytest tests -q --disable-warnings`

**Environment:** local Python runtime, FastAPI + HTTPX TestClient, isolated temporary SQLite database per API test, synthetic ACME/NOVA records, no internet/model/tool execution.

**Result:** 153 tests passed locally (65 earlier policy regression tests plus 88 additional HTTP and security checks). See GitHub Actions for independently rerun results on the repository commit; do not assume they are green without checking.

Evidence artifacts can be rebuilt reproducibly with `python scripts/build_report.py`, generating an HTML summary and JUnit XML output in `reports/`. Tests do not access external customer accounts, email, networks, or production models.

Known limitations are detailed in `THREAT_MODEL.md`.