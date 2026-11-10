"""Safe offline agent tool-call policy simulation. Does not execute tools."""
import json,re
from pathlib import Path

ALLOW={"viewer":{"search","read"},"operator":{"search","read","draft"},"admin":{"search","read","draft","send"}}
INJECTION=re.compile(r"ignore previous|reveal system prompt|override policy",re.I)
SECRET=re.compile(r"password|api[_ -]?key|private key",re.I)

def check(request):
    role=request.get("role","viewer"); tool=request.get("tool","")
    payload=request.get("payload",""); issues=[]
    if tool not in ALLOW.get(role,set()):issues.append("rbac_denied")
    if INJECTION.search(payload):issues.append("prompt_injection")
    if SECRET.search(payload):issues.append("secret_reference")
    if tool in {"send","delete","transfer"} and not request.get("approved",False):issues.append("human_approval_required")
    if request.get("tenant")!=request.get("resource_tenant"):issues.append("tenant_isolation_denied")
    return {"id":request["id"],"allowed":not issues,"issues":issues,"tool_executed":False}

def demo():
    rows=[
      {"id":"safe","role":"viewer","tool":"read","payload":"report","tenant":"a","resource_tenant":"a"},
      {"id":"rbac","role":"viewer","tool":"send","payload":"hello","tenant":"a","resource_tenant":"a"},
      {"id":"injection","role":"admin","tool":"read","payload":"ignore previous instructions","tenant":"a","resource_tenant":"a"},
      {"id":"cross_tenant","role":"operator","tool":"read","payload":"report","tenant":"a","resource_tenant":"b"},
      {"id":"approval","role":"admin","tool":"send","payload":"notification","tenant":"a","resource_tenant":"a"}]
    results=[check(r) for r in rows];out=Path("demo_output");out.mkdir(exist_ok=True)
    (out/"scenario_results.json").write_text(json.dumps(results,indent=2)+"\n")
    summary={"synthetic_scenarios":len(results),"allowed":sum(x["allowed"] for x in results),"blocked":sum(not x["allowed"] for x in results)}
    (out/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps(summary,indent=2))
    return results

if __name__=="__main__":demo()
