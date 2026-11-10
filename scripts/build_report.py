"""Execute real pytest checks and render a small offline HTML evidence summary."""
from __future__ import annotations

import html
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    junit = REPORTS / "junit.xml"
    result = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q", f"--junitxml={junit}"], cwd=ROOT, check=False)
    tree = ET.parse(junit)
    root = tree.getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        raise SystemExit("Could not parse pytest JUnit output")
    count = int(suite.attrib.get("tests", 0))
    failures = int(suite.attrib.get("failures", 0))
    errors = int(suite.attrib.get("errors", 0))
    skipped = int(suite.attrib.get("skipped", 0))
    passed = count - failures - errors - skipped
    status = "PASS" if result.returncode == 0 else "FAIL"
    rows = []
    for case in suite.findall("testcase"):
        name = html.escape(case.attrib.get("name", "unknown"))
        group = html.escape(case.attrib.get("classname", "tests"))
        failed = case.find("failure") is not None or case.find("error") is not None
        rows.append(f"<tr><td>{group}</td><td>{name}</td><td class={'bad' if failed else 'good'}>{'FAIL' if failed else 'PASS'}</td></tr>")
    page = f"""<!doctype html><html lang='en'><meta charset='utf-8'><title>SentinelDesk Security Test Evidence</title>
<style>body{{font-family:system-ui;background:#0e1728;color:#e7f0ff;margin:40px auto;max-width:1100px;padding:0 18px}}.box{{border:1px solid #344761;border-radius:12px;padding:25px;background:#142238;margin:15px 0}}.cards{{display:flex;gap:18px;flex-wrap:wrap}}.cards>b{{padding:15px;background:#243752;border-radius:8px}}.good{{color:#53e5b2}}.bad{{color:#ff9494}}table{{border-collapse:collapse;width:100%}}td,th{{padding:9px;border-bottom:1px solid #304058;text-align:left;font-size:13px}}p{{color:#adbed8}}</style>
<h1>SentinelDesk | Security Assurance Evidence</h1><p>Local, reproducible synthetic agent / API test run — not a live penetration test</p>
<div class='box'><h2>Status: <span class={'good' if result.returncode==0 else 'bad'}>{status}</span></h2><div class='cards'><b>{count} Total</b><b>{passed} Passed</b><b>{failures} Failed</b><b>{errors} Errors</b><b>{skipped} Skipped</b></div><p>Run timestamp (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}</p></div>
<div class='box'><h2>Executed test cases</h2><table><tr><th>Class</th><th>Case</th><th>Result</th></tr>{''.join(rows)}</table></div>
<p>All test data, personas and customer tickets are fictional. See README and docs/THREAT_MODEL.md for scope.</p></html>"""
    destination = REPORTS / "security-summary.html"
    destination.write_text(page, encoding="utf-8")
    print(f"Evidence generated: {destination}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())