"""HTTP-level tests against isolated SQLite DBs and local FastAPI TestClient."""
import sqlite3
import pytest


def triage(client, headers, ticket="AC-101"):
    return client.post("/v1/agent/triage", headers=headers, json={"ticket_id": ticket})


def make_draft(client, operator, ticket="AC-101"):
    response = triage(client, operator, ticket)
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "drafted", response.text
    return response.json()["draft_id"]


def test_health_ready(client):
    assert client.get("/healthz").json() == {"status": "ok", "service": "sentineldesk", "mode": "demo"}


def test_dashboard_served(client):
    assert "SentinelDesk" in client.get("/").text


def test_openapi_contract_exists(client):
    result = client.get("/openapi.json")
    assert result.status_code == 200
    assert "/v1/agent/triage" in result.json()["paths"]


def test_no_credentials_401(client):
    assert client.get("/v1/me").status_code == 401


@pytest.mark.parametrize("header", ["", "Basic xxx", "Bearer wrong", "Bearer ", "bearer local-acme-admin"])
def test_bad_bearer_credentials_fail(client, header):
    result = client.get("/v1/me", headers={"Authorization": header})
    assert result.status_code == 401
    assert "local-acme" not in result.text


def test_valid_server_identity(client, acme_operator):
    assert client.get("/v1/me", headers=acme_operator).json() == {
        "tenant": "acme", "role": "operator", "actor": "agent-1"
    }


def test_viewer_can_read_own_ticket(client, acme_viewer):
    assert client.get("/v1/tickets/AC-101", headers=acme_viewer).status_code == 200


def test_viewer_cannot_generate_agent_draft(client, acme_viewer):
    assert triage(client, acme_viewer).status_code == 403


@pytest.mark.parametrize("ticket", ["NV-201", "NV-202"])
def test_cross_tenant_ticket_is_indistinguishable_from_missing(client, acme_operator, ticket):
    result = client.get("/v1/tickets/" + ticket, headers=acme_operator)
    assert result.status_code == 404


def test_cross_tenant_agent_action_blocked(client, acme_operator):
    assert triage(client, acme_operator, "NV-201").status_code == 404


def test_other_tenant_can_read_own_data(client, nova_operator):
    assert client.get("/v1/tickets/NV-201", headers=nova_operator).status_code == 200


def test_knowledge_retrieval_is_tenant_scoped(client, acme_operator):
    data = client.post("/v1/knowledge/search", headers=acme_operator, json={"query": "delivery"}).json()
    assert [x["id"] for x in data["matches"]] == ["KB-AC-1"]
    assert "nova" not in str(data).lower()


def test_nova_retrieval_is_tenant_scoped(client, nova_operator):
    data = client.post("/v1/knowledge/search", headers=nova_operator, json={"query": "delivery"}).json()
    assert [x["id"] for x in data["matches"]] == ["KB-NV-1"]


def test_search_query_sql_injection_is_not_executed(client, acme_operator):
    result = client.post("/v1/knowledge/search", headers=acme_operator, json={"query": "' OR 1=1 --"})
    assert result.status_code == 200
    assert result.json()["matches"] == []


@pytest.mark.parametrize("query", ["", "x", "a" * 121, 999, None])
def test_search_validation_rejects_bad_inputs(client, acme_operator, query):
    assert client.post("/v1/knowledge/search", headers=acme_operator, json={"query": query}).status_code == 422


def test_knowledge_injection_document_is_quarantined(client, acme_operator):
    data = client.post("/v1/knowledge/search", headers=acme_operator, json={"query": "onboarding"}).json()
    assert data["matches"][0]["quarantined"] is True
    assert "reveal system prompt" not in str(data)


def test_legitimate_triage_creates_draft(client, acme_operator):
    data = triage(client, acme_operator).json()
    assert data["decision"] == "drafted"
    assert data["approval_required"] is True
    assert data["source"] == "KB-AC-1"
    assert "3-5 business days" in data["message"]
    assert data["delivery_channel"] == "sandbox"


def test_refund_has_correct_tenant_knowledge(client, acme_operator):
    data = triage(client, acme_operator, "AC-102").json()
    assert data["source"] == "KB-AC-2"
    assert "5 business days" in data["message"]


def test_ticket_prompt_injection_is_blocked(client, acme_operator):
    data = triage(client, acme_operator, "AC-103").json()
    assert data["decision"] == "blocked"
    assert "ticket:prompt_injection_indicator" in data["flags"]
    assert data["draft_id"] is None


def test_indirect_knowledge_prompt_injection_is_blocked(client, acme_operator):
    data = triage(client, acme_operator, "AC-105").json()
    assert data["decision"] == "blocked"
    assert "knowledge:prompt_injection_indicator" in data["flags"]


def test_double_encoded_prompt_injection_is_blocked(client, nova_operator):
    data = triage(client, nova_operator, "NV-202").json()
    assert data["decision"] == "blocked"


def test_no_reflection_of_untrusted_ticket_in_reply(client, acme_operator):
    data = triage(client, acme_operator).json()
    assert "Where is my order" not in data["message"]


def test_sandbox_outbox_empty_before_approval(client, acme_admin, acme_operator):
    make_draft(client, acme_operator)
    assert client.get("/v1/outbox", headers=acme_admin).json()["items"] == []


def test_operator_cannot_approve(client, acme_operator):
    draft_id = make_draft(client, acme_operator)
    assert client.post(f"/v1/approvals/{draft_id}", headers=acme_operator).status_code == 403


def test_approval_rejects_unknown_draft(client, acme_admin):
    assert client.post("/v1/approvals/missing", headers=acme_admin).status_code == 404


def test_other_tenant_cannot_approve(client, acme_operator, nova_admin):
    draft_id = make_draft(client, acme_operator)
    assert client.post(f"/v1/approvals/{draft_id}", headers=nova_admin).status_code == 404


def test_admin_cannot_self_approve(client, acme_admin):
    draft_id = make_draft(client, acme_admin)
    assert client.post(f"/v1/approvals/{draft_id}", headers=acme_admin).status_code == 403


def test_approval_creates_bound_record(client, acme_operator, acme_admin):
    draft_id = make_draft(client, acme_operator)
    data = client.post(f"/v1/approvals/{draft_id}", headers=acme_admin).json()
    assert data == {"draft_id": draft_id, "status": "approved", "approved_by": "supervisor-1"}


def test_approval_replay_rejected(client, acme_operator, acme_admin):
    draft_id = make_draft(client, acme_operator)
    client.post(f"/v1/approvals/{draft_id}", headers=acme_admin)
    assert client.post(f"/v1/approvals/{draft_id}", headers=acme_admin).status_code == 409


def test_send_without_approval_denied(client, acme_operator):
    draft_id = make_draft(client, acme_operator)
    assert client.post(f"/v1/actions/send/{draft_id}", headers=acme_operator).status_code == 409


def test_send_with_verified_approval_creates_sandbox_record(client, acme_operator, acme_admin):
    draft_id = make_draft(client, acme_operator)
    client.post(f"/v1/approvals/{draft_id}", headers=acme_admin)
    result = client.post(f"/v1/actions/send/{draft_id}", headers=acme_operator)
    assert result.status_code == 200
    assert result.json()["external_delivery"] is False
    outbox = client.get("/v1/outbox", headers=acme_admin).json()["items"]
    assert len(outbox) == 1
    assert outbox[0]["channel"] == "sandbox"


def test_sending_twice_is_blocked(client, acme_operator, acme_admin):
    draft_id = make_draft(client, acme_operator)
    client.post(f"/v1/approvals/{draft_id}", headers=acme_admin)
    assert client.post(f"/v1/actions/send/{draft_id}", headers=acme_operator).status_code == 200
    assert client.post(f"/v1/actions/send/{draft_id}", headers=acme_operator).status_code == 409
    assert len(client.get("/v1/outbox", headers=acme_admin).json()["items"]) == 1


def test_cross_tenant_send_denied(client, acme_operator, acme_admin, nova_operator):
    draft_id = make_draft(client, acme_operator)
    client.post(f"/v1/approvals/{draft_id}", headers=acme_admin)
    assert client.post(f"/v1/actions/send/{draft_id}", headers=nova_operator).status_code == 404


def test_viewer_cannot_send_even_approved(client, acme_operator, acme_admin, acme_viewer):
    draft_id = make_draft(client, acme_operator)
    client.post(f"/v1/approvals/{draft_id}", headers=acme_admin)
    assert client.post(f"/v1/actions/send/{draft_id}", headers=acme_viewer).status_code == 403


def test_outbox_admin_only(client, acme_operator):
    assert client.get("/v1/outbox", headers=acme_operator).status_code == 403


def test_audit_admin_only(client, acme_operator):
    assert client.get("/v1/audit", headers=acme_operator).status_code == 403


def test_audit_contains_workflow_events(client, acme_operator, acme_admin):
    draft_id = make_draft(client, acme_operator)
    client.post(f"/v1/approvals/{draft_id}", headers=acme_admin)
    client.post(f"/v1/actions/send/{draft_id}", headers=acme_operator)
    events = [x["event"] for x in client.get("/v1/audit", headers=acme_admin).json()["items"]]
    assert events == ["sandbox_send", "approve", "triage"]


def test_audit_redacts_tokens_and_customer_message(client, acme_operator, acme_admin):
    make_draft(client, acme_operator)
    audit = str(client.get("/v1/audit", headers=acme_admin).json())
    assert "local-acme-operator" not in audit
    assert "Where is my order?" not in audit


def test_audit_does_not_leak_other_tenant_events(client, acme_operator, acme_admin):
    triage(client, acme_operator)
    nova = {"Authorization": "Bearer local-nova-operator"}
    triage(client, nova, "NV-201")
    result = client.get("/v1/audit", headers=acme_admin).json()["items"]
    assert len(result) == 1
    assert all(x["actor"] == "agent-1" for x in result)


@pytest.mark.parametrize("limit", [-1, 0, 101, "nonsense"])
def test_audit_pagination_input_bound(client, acme_admin, limit):
    assert client.get("/v1/audit", headers=acme_admin, params={"limit": limit}).status_code == 422


def test_audit_contains_blocked_attempt(client, acme_operator, acme_admin):
    triage(client, acme_operator, "AC-103")
    events = client.get("/v1/audit", headers=acme_admin).json()["items"]
    assert events[0]["outcome"] == "blocked"


def test_api_does_not_advertise_real_email(client):
    spec = client.get("/openapi.json").json()
    assert spec["info"]["title"].startswith("SentinelDesk")
    assert not any("smtp" in path.lower() for path in spec["paths"])