from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

from .action import Action, get_attachments, get_body, get_recipients, registrable_domain


SENSITIVE_TOOLS = {
    "send_email",
    "send_message",
    "http_post",
    "shell_exec",
    "file_write",
    "upload",
    "post_webhook",
}

INTERNAL_DOMAINS = {"acme.com"}

ZERO_WIDTH_BIDI_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])")
SECRET_HINT_RE = re.compile(
    r"(?i)\b(password|passwd|api[_ -]?key|secret|token|private\s*key|customer_data|pii|ssn|iban)\b"
)
URL_RE = re.compile(r"https?://[^\s)\]>\"']+")


@dataclass(slots=True)
class Finding:
    policy_id: str
    decision: str
    severity: str
    reason: str


def normalize(text: str) -> str:
    base = ZERO_WIDTH_BIDI_RE.sub("", text or "")
    decoded_chunks: list[str] = []
    for token in BASE64_CANDIDATE_RE.findall(base):
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = raw.decode("utf-8", errors="ignore").strip()
            if decoded and any(c.isalnum() for c in decoded):
                decoded_chunks.append(decoded)
        except Exception:
            continue
    if decoded_chunks:
        return base + "\n" + "\n".join(decoded_chunks)
    return base


def _contains_any(hay: str, needles: list[str]) -> bool:
    h = (hay or "").lower()
    return any(n.lower() in h for n in needles)


def _recipient_external(action: Action, allowlist: set[str] | None = None) -> bool:
    allow = {d.lower() for d in (allowlist or INTERNAL_DOMAINS)}
    recipients = get_recipients(action.args)
    if not recipients:
        return False
    for r in recipients:
        dom = registrable_domain(r)
        if dom and dom not in allow:
            return True
    return False


def _match_rule(action: Action, rule: dict[str, Any]) -> bool:
    when = rule.get("when", {}) or {}

    tool = when.get("tool")
    if tool is not None and action.tool != tool:
        return False

    action_type = when.get("action_type")
    if action_type is not None and action.action_type != action_type:
        return False

    agent_id = when.get("agent_id")
    if agent_id is not None and action.agent_id != agent_id:
        return False

    recipient_domain_not_in = when.get("recipient_domain_not_in")
    if recipient_domain_not_in is not None:
        allowlist = {d.lower() for d in recipient_domain_not_in}
        recips = get_recipients(action.args)
        if not recips:
            return False
        if not any(registrable_domain(r) not in allowlist for r in recips):
            return False

    has_attachment = when.get("has_attachment")
    if has_attachment is True and not get_attachments(action.args):
        return False
    if has_attachment is False and get_attachments(action.args):
        return False

    attachment_contains_any = when.get("attachment_contains_any")
    if attachment_contains_any is not None:
        attachment_blob = "\n".join(get_attachments(action.args))
        if not _contains_any(attachment_blob, list(attachment_contains_any)):
            return False

    body_contains_any = when.get("body_contains_any")
    if body_contains_any is not None:
        body = normalize(get_body(action.args))
        if not _contains_any(body, list(body_contains_any)):
            return False

    command_matches_any = when.get("command_matches_any")
    if command_matches_any is not None:
        command = str(action.args.get("command", ""))
        if not any(re.search(rx, command, flags=re.IGNORECASE) for rx in command_matches_any):
            return False

    return True


def evaluate_policies(action: Action, rules: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules or []:
        if _match_rule(action, rule):
            findings.append(
                Finding(
                    policy_id=str(rule.get("id", "unknown.policy")),
                    decision=str(rule.get("action", "log_only")),
                    severity=str(rule.get("severity", "medium")),
                    reason=str(rule.get("description", "policy matched")),
                )
            )
    return findings


def heuristic_findings(action: Action) -> list[Finding]:
    if action.tool not in SENSITIVE_TOOLS:
        return []

    findings: list[Finding] = []
    external = _recipient_external(action)
    scan_text = normalize(get_body(action.args) + "\n" + "\n".join(get_attachments(action.args)))
    has_secret = bool(SECRET_HINT_RE.search(scan_text))

    if external and has_secret:
        findings.append(
            Finding(
                policy_id="heuristic.external_secret_exfil",
                decision="block",
                severity="critical",
                reason="Potential exfiltration to external recipient with sensitive content.",
            )
        )
    elif action.source_context == "untrusted" and external:
        findings.append(
            Finding(
                policy_id="heuristic.untrusted_external_send",
                decision="require_approval",
                severity="high",
                reason="Untrusted-origin action targeting external recipient.",
            )
        )

    return findings


def message_findings(action: Action) -> list[Finding]:
    if action.action_type != "message":
        return []

    findings: list[Finding] = []
    text = normalize(action.raw_output or action.text_blob())

    if action.source_context == "untrusted" and SECRET_HINT_RE.search(text):
        findings.append(
            Finding(
                policy_id="heuristic.message_sensitive_disclosure",
                decision="block",
                severity="high",
                reason="Message output contains sensitive content from an untrusted context.",
            )
        )

    for url in URL_RE.findall(text):
        parsed = urlparse(url)
        if not parsed.netloc:
            continue
        domain = registrable_domain(parsed.netloc)
        if domain in INTERNAL_DOMAINS:
            continue
        if not parsed.query:
            continue

        q = parsed.query.lower()
        has_base64_word = "base64" in q

        has_b64_blob = False
        for values in parse_qs(parsed.query, keep_blank_values=True).values():
            for v in values:
                if BASE64_CANDIDATE_RE.search(v):
                    has_b64_blob = True
                    break
            if has_b64_blob:
                break

        if has_base64_word or has_b64_blob:
            findings.append(
                Finding(
                    policy_id="heuristic.message_encoded_url_exfil",
                    decision="block",
                    severity="critical",
                    reason="Message output contains external URL with encoded query payload.",
                )
            )
            break

    return findings

