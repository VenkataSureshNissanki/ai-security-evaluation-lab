"""SentinelDesk API: tenant-scoped support-agent actions with independent approval.

Demo mode is explicit; this application has no production authentication provider.
All "send" actions write into a local SQLite sandbox outbox, never to email/SMS.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .security import safe_reference_url, screen_untrusted
from .storage import audit, connect, seed_database

ROOT = Path(__file__).resolve().parent

class SearchQuery(BaseModel):
    query: str = Field(min_length=2, max_length=120)

class TicketAction(BaseModel):
    ticket_id: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9-]+$")

class Principal(BaseModel):
    tenant: str
    role: str
    actor: str


def create_app(db_path: str | None = None, demo_mode: bool = False) -> FastAPI:
    target = db_path or os.getenv("SENTINEL_DB_PATH", "./sentineldesk.sqlite")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        seed_database(target, demo_mode)
        yield

    app = FastAPI(title="SentinelDesk | AI Agent Security Gateway", version="1.0.0", lifespan=lifespan,
                  description="Fictional B2B helpdesk and local AI-agent authorization demo. NO external messages or model calls.")

    def current_user(authorization: Annotated[str | None, Header()] = None) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})
        token = authorization[7:]
        if not token or len(token) > 256:
            raise HTTPException(401, "Invalid token")
        with connect(target) as db:
            result = db.execute("SELECT tenant, role, actor FROM principals WHERE key_hash=?",
                                (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if result is None:
            raise HTTPException(401, "Invalid token")
        return Principal(**dict(result))

    def require(*roles: str):
        def authorize(principal: Principal = Depends(current_user)) -> Principal:
            if principal.role not in roles:
                raise HTTPException(403, "Role not permitted")
            return principal
        return authorize

    @app.get("/healthz")
    def health():
        return {"status": "ok", "service": "sentineldesk", "mode": "demo" if demo_mode else "no-demo-credentials"}

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(ROOT / "static" / "index.html")

    @app.get("/v1/me")
    def me(principal: Principal = Depends(current_user)):
        return principal

    @app.get("/v1/tickets/{ticket_id}")
    def get_ticket(ticket_id: str, principal: Principal = Depends(require("viewer", "operator", "admin"))):
        with connect(target) as db:
            item = db.execute("SELECT id, subject, customer_message FROM tickets WHERE id=? AND tenant=?",
                              (ticket_id, principal.tenant)).fetchone()
        if item is None:
            raise HTTPException(404, "Ticket not found")
        return dict(item)

    @app.post("/v1/knowledge/search")
    def search_knowledge(input: SearchQuery, principal: Principal = Depends(require("viewer", "operator", "admin"))):
        # Parameterized query. No SQL generated from untrusted input.
        with connect(target) as db:
            items = db.execute("SELECT id, topic, title, body, url FROM knowledge WHERE tenant=?",
                               (principal.tenant,)).fetchall()
        terms = input.query.casefold().split()
        matches = [dict(item) for item in items if any(term in (item["topic"] + " " + item["title"]).casefold() for term in terms)]
        return {"matches": [{"id": d["id"], "title": d["title"], "topic": d["topic"],
                              "url": d["url"], "quarantined": bool(screen_untrusted(d["body"]))}
                             for d in matches[:10]]}

    @app.post("/v1/agent/triage")
    def triage(action: TicketAction, principal: Principal = Depends(require("operator", "admin"))):
        with connect(target) as db:
            ticket = db.execute("SELECT * FROM tickets WHERE id=? AND tenant=?",
                                (action.ticket_id, principal.tenant)).fetchone()
            if ticket is None:
                audit(db, principal.tenant, principal.actor, "triage", action.ticket_id, "ticket_not_found")
                raise HTTPException(404, "Ticket not found")
            msg = ticket["customer_message"]
            # Ticket text is data, never executable instructions.
            flags = ["ticket:" + f for f in screen_untrusted(msg)]
            subject = ticket["subject"].lower()
            topic = "refund" if "refund" in subject else "delivery" if "deliver" in subject or "order" in subject else "account" if "account" in subject else "onboarding"
            doc = db.execute("SELECT * FROM knowledge WHERE tenant=? AND topic=? ORDER BY id LIMIT 1",
                             (principal.tenant, topic)).fetchone()
            if doc:
                flags += ["knowledge:" + f for f in screen_untrusted(doc["body"])]
                if not safe_reference_url(doc["url"]):
                    flags.append("knowledge:unsafe_reference_url")
            if flags:
                audit(db, principal.tenant, principal.actor, "triage", action.ticket_id, "blocked")
                return {"decision": "blocked", "ticket_id": action.ticket_id, "flags": flags, "draft_id": None}
            # This deterministic template replaces external LLM calls; security policies are enforced independently.
            summary = doc["body"] if doc else "A support specialist will review this request."
            body = f"Hello, thanks for contacting support. {summary} A team member will confirm next steps."
            draft_id = str(uuid.uuid4())
            db.execute("INSERT INTO drafts (id,ticket_id,tenant,creator,body,status,source_id,flags) VALUES (?,?,?,?,?,?,?,?)",
                       (draft_id, action.ticket_id, principal.tenant, principal.actor, body, "pending_approval", doc["id"] if doc else None, "[]"))
            audit(db, principal.tenant, principal.actor, "triage", draft_id, "draft_created")
        return {"decision": "drafted", "draft_id": draft_id, "ticket_id": action.ticket_id, "message": body,
                "source": doc["id"] if doc else None, "approval_required": True, "delivery_channel": "sandbox"}

    @app.post("/v1/approvals/{draft_id}")
    def approve(draft_id: str, principal: Principal = Depends(require("admin"))):
        with connect(target) as db:
            db.execute("BEGIN IMMEDIATE")
            draft = db.execute("SELECT * FROM drafts WHERE id=? AND tenant=?", (draft_id, principal.tenant)).fetchone()
            if draft is None:
                raise HTTPException(404, "Draft not found")
            if draft["status"] != "pending_approval":
                raise HTTPException(409, "Draft is not pending approval")
            if draft["creator"] == principal.actor:
                raise HTTPException(403, "Separation of duties: creator cannot approve own draft")
            db.execute("INSERT INTO approvals (draft_id,tenant,approver) VALUES (?,?,?)", (draft_id, principal.tenant, principal.actor))
            db.execute("UPDATE drafts SET status='approved' WHERE id=? AND tenant=?", (draft_id, principal.tenant))
            audit(db, principal.tenant, principal.actor, "approve", draft_id, "approved")
            db.commit()
        return {"draft_id": draft_id, "status": "approved", "approved_by": principal.actor}

    @app.post("/v1/actions/send/{draft_id}")
    def send(draft_id: str, principal: Principal = Depends(require("operator", "admin"))):
        with connect(target) as db:
            db.execute("BEGIN IMMEDIATE")
            draft = db.execute("SELECT * FROM drafts WHERE id=? AND tenant=?", (draft_id, principal.tenant)).fetchone()
            if draft is None:
                raise HTTPException(404, "Draft not found")
            if draft["status"] != "approved":
                raise HTTPException(409, "Draft must be approved and not already sent")
            approval = db.execute("SELECT * FROM approvals WHERE draft_id=? AND tenant=?", (draft_id, principal.tenant)).fetchone()
            if approval is None or approval["approver"] == draft["creator"]:
                raise HTTPException(403, "Independent approval missing")
            delivery_id = str(uuid.uuid4())
            db.execute("INSERT INTO outbox (id,draft_id,tenant,message) VALUES (?,?,?,?)",
                       (delivery_id, draft_id, principal.tenant, draft["body"]))
            db.execute("UPDATE drafts SET status='sent_to_sandbox' WHERE id=? AND tenant=?", (draft_id, principal.tenant))
            audit(db, principal.tenant, principal.actor, "sandbox_send", draft_id, "recorded")
            db.commit()
        return {"delivery_id": delivery_id, "draft_id": draft_id, "status": "sent_to_sandbox", "external_delivery": False}

    @app.get("/v1/outbox")
    def outbox(principal: Principal = Depends(require("admin"))):
        with connect(target) as db:
            rows = db.execute("SELECT id,draft_id,channel,created_at FROM outbox WHERE tenant=? ORDER BY created_at DESC LIMIT 100",
                              (principal.tenant,)).fetchall()
        return {"items": [dict(row) for row in rows]}

    @app.get("/v1/audit")
    def get_audit(limit: int = Query(default=30, ge=1, le=100),
                  principal: Principal = Depends(require("admin"))):
        with connect(target) as db:
            rows = db.execute("SELECT id,actor,event,resource_id,outcome,created_at FROM audit WHERE tenant=? ORDER BY id DESC LIMIT ?",
                              (principal.tenant, limit)).fetchall()
        return {"items": [dict(row) for row in rows]}

    return app

app = create_app(demo_mode=os.getenv("SENTINEL_DEMO_MODE") == "1")