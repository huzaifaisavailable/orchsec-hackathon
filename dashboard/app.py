from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from orchsec.action import Action
from orchsec.engine import OrchSec

STATIC_DIR = Path(__file__).parent / "static"
DEFAULT_POLICY = Path("policies/default.yml")
DEFAULT_AUDIT = Path("audit.log.jsonl")


class EvaluateRequest(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    source_context: str = "untrusted"
    action_type: str = "tool_call"
    raw_output: str = ""
    agent_id: str = "dashboard-agent"


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _load_policies(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules = data.get("rules", [])
    return rules if isinstance(rules, list) else []


def create_app(
    *,
    policy_path: str = "policies/default.yml",
    audit_path: str = "audit.log.jsonl",
    use_judge: bool = False,
) -> FastAPI:
    app = FastAPI(title="OrchSec Dashboard", version="1.0.0")
    policy_file = Path(policy_path)
    audit_file = Path(audit_path)

    orch = OrchSec(
        policy_path=str(policy_file),
        audit_path=str(audit_file),
        use_judge=use_judge,
        fail_closed=True,
    )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/stats")
    def stats() -> dict[str, Any]:
        events = _read_audit(audit_file)
        decisions = Counter(e.get("decision", "UNKNOWN") for e in events)
        severities = Counter(e.get("severity", "unknown") for e in events)
        tools = Counter(e.get("tool", "unknown") for e in events)
        policies = Counter(
            e.get("policy_id") or "none"
            for e in events
            if e.get("decision") in {"BLOCK", "REQUIRE_APPROVAL"}
        )
        return {
            "total": len(events),
            "blocks": decisions.get("BLOCK", 0),
            "allows": decisions.get("ALLOW", 0),
            "approvals": decisions.get("REQUIRE_APPROVAL", 0),
            "by_severity": dict(severities),
            "by_tool": dict(tools),
            "top_policies": dict(policies.most_common(5)),
        }

    @app.get("/api/events")
    def events(
        limit: int = Query(50, ge=1, le=500),
        decision: str | None = None,
        tool: str | None = None,
    ) -> list[dict[str, Any]]:
        records = _read_audit(audit_file)
        records.reverse()
        if decision:
            records = [r for r in records if r.get("decision") == decision.upper()]
        if tool:
            records = [r for r in records if r.get("tool") == tool]
        return records[:limit]

    @app.get("/api/policies")
    def policies() -> list[dict[str, Any]]:
        return _load_policies(policy_file)

    @app.post("/api/evaluate")
    def evaluate(req: EvaluateRequest) -> dict[str, Any]:
        action = Action(
            tool=req.tool,
            args=req.args,
            source_context=req.source_context,
            action_type=req.action_type,
            raw_output=req.raw_output,
            agent_id=req.agent_id,
        )
        result = orch.evaluate(action)
        return {
            "decision": result.decision,
            "reason": result.reason,
            "severity": result.severity,
            "trace_id": result.trace_id,
            "policy_id": result.policy_id,
            "judged_by": result.judged_by,
            "findings": [
                {
                    "policy_id": f.policy_id,
                    "decision": f.decision,
                    "severity": f.severity,
                    "reason": f.reason,
                }
                for f in result.findings
            ],
        }

    @app.get("/")
    def index() -> FileResponse:
        index_path = STATIC_DIR / "index.html"
        if not index_path.exists():
            raise HTTPException(status_code=404, detail="Dashboard UI not found")
        return FileResponse(index_path)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
