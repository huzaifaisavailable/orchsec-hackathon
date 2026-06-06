from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .action import Action, redact, redact_args
from .detectors import (
    SENSITIVE_TOOLS,
    Finding,
    evaluate_policies,
    heuristic_findings,
    message_findings,
)
from .judge import DEFAULT_JUDGE_BASE_URL, DEFAULT_JUDGE_MODEL, judge_action


ALLOW = "ALLOW"
BLOCK = "BLOCK"
REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
REDACT = "REDACT"
LOG_ONLY = "LOG_ONLY"


@dataclass(slots=True)
class Decision:
    decision: str
    reason: str
    severity: str
    trace_id: str
    policy_id: str = ""
    judged_by: str = "deterministic"
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.decision in {BLOCK, REQUIRE_APPROVAL}


class OrchSec:
    def __init__(
        self,
        policy_path: str = "policies/default.yml",
        *,
        audit_path: str = "audit.log.jsonl",
        use_judge: bool = True,
        fail_closed: bool = True,
        judge_model: str = DEFAULT_JUDGE_MODEL,
        judge_base_url: str | None = DEFAULT_JUDGE_BASE_URL,
    ) -> None:
        self.policy_path = Path(policy_path)
        self.audit_path = Path(audit_path)
        self.use_judge = use_judge
        self.fail_closed = fail_closed
        self.judge_model = judge_model
        self.judge_base_url = judge_base_url
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict[str, Any]]:
        if not self.policy_path.exists():
            return []
        data = yaml.safe_load(self.policy_path.read_text(encoding="utf-8")) or {}
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            return []
        return rules

    def evaluate(self, action: Action) -> Decision:
        findings: list[Finding] = []
        findings.extend(evaluate_policies(action, self.rules))
        findings.extend(heuristic_findings(action))
        findings.extend(message_findings(action))

        det_block = [f for f in findings if f.decision == "block"]
        det_approval = [f for f in findings if f.decision == "require_approval"]

        if det_block:
            f = det_block[0]
            d = Decision(
                decision=BLOCK,
                reason=f.reason,
                severity=f.severity,
                trace_id=action.trace_id,
                policy_id=f.policy_id,
                judged_by="deterministic",
                findings=findings,
            )
            self._audit(action, d)
            return d

        should_judge = self.use_judge and (
            bool(findings)
            or (action.tool in SENSITIVE_TOOLS and action.source_context == "untrusted")
        )

        if should_judge:
            verdict = judge_action(
                action,
                model=self.judge_model,
                base_url=self.judge_base_url,
            )
            if verdict.verdict == "block" and (verdict.available or self.fail_closed):
                d = Decision(
                    decision=BLOCK,
                    reason=verdict.reason,
                    severity="high",
                    trace_id=action.trace_id,
                    policy_id="llm.judge",
                    judged_by="llm" if not findings else "both",
                    findings=findings,
                )
                self._audit(action, d)
                return d

        if det_approval:
            f = det_approval[0]
            d = Decision(
                decision=REQUIRE_APPROVAL,
                reason=f.reason,
                severity=f.severity,
                trace_id=action.trace_id,
                policy_id=f.policy_id,
                judged_by="deterministic",
                findings=findings,
            )
            self._audit(action, d)
            return d

        d = Decision(
            decision=ALLOW,
            reason="No blocking policy matched.",
            severity="low",
            trace_id=action.trace_id,
            policy_id="",
            judged_by="deterministic",
            findings=findings,
        )
        self._audit(action, d)
        return d

    def _audit(self, action: Action, decision: Decision) -> None:
        record = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "trace_id": action.trace_id,
            "agent_id": action.agent_id,
            "tool": action.tool,
            "source_context": action.source_context,
            "decision": decision.decision,
            "severity": decision.severity,
            "policy_id": decision.policy_id,
            "judged_by": decision.judged_by,
            "reason": decision.reason,
            "attempted_action": {
                "tool": action.tool,
                "action_type": action.action_type,
                "args": redact_args(action.args),
                "raw_output": redact(action.raw_output) if action.raw_output else "",
            },
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

