from __future__ import annotations

import copy
import re
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
SECRET_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|token|private[_-]?key)\b\s*[:=]\s*([^\s,;]+)"
)


def _short_trace() -> str:
    return uuid.uuid4().hex[:12]


def _flatten(value: Any) -> list[str]:
    chunks: list[str] = []
    if value is None:
        return chunks
    if isinstance(value, str):
        chunks.append(value)
        return chunks
    if isinstance(value, dict):
        for k, v in value.items():
            chunks.append(str(k))
            chunks.extend(_flatten(v))
        return chunks
    if isinstance(value, (list, tuple, set)):
        for item in value:
            chunks.extend(_flatten(item))
        return chunks
    chunks.append(str(value))
    return chunks


def _split_multi(value: str) -> list[str]:
    return [x.strip() for x in re.split(r"[,;\s]+", value or "") if x.strip()]


def registrable_domain(addr: str) -> str:
    """
    Return a simplified registrable domain as the last two labels.
    This intentionally avoids substring matching tricks such as
    company.com.attacker.io -> attacker.io.
    """
    if not addr:
        return ""

    text = addr.strip().lower()
    if "@" in text and not text.startswith(("http://", "https://")):
        text = text.split("@")[-1]

    if text.startswith(("http://", "https://")):
        text = urlparse(text).netloc or text

    text = text.split(":")[0].strip("[]()<>\"' ")
    labels = [p for p in text.split(".") if p]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return text


def get_recipients(args: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("to", "recipient", "recipients", "cc", "bcc"):
        item = args.get(key)
        if item is None:
            continue
        if isinstance(item, str):
            values.extend(_split_multi(item))
        elif isinstance(item, (list, tuple, set)):
            for v in item:
                values.extend(_split_multi(str(v)))
        else:
            values.extend(_split_multi(str(item)))
    return values


def get_body(args: dict[str, Any]) -> str:
    return "\n".join(str(args.get(k, "")) for k in ("body", "content", "text", "message") if args.get(k) is not None)


def get_attachments(args: dict[str, Any]) -> list[str]:
    raw = args.get("attachments")
    if raw is None:
        raw = args.get("attachment")
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (list, tuple, set)):
        return [str(x) for x in raw]
    return [str(raw)]


def redact(text: str) -> str:
    if text is None:
        return ""
    out = str(text)
    out = EMAIL_RE.sub("[REDACTED_EMAIL]", out)
    out = CARD_RE.sub("[REDACTED_CARD]", out)
    out = AWS_KEY_RE.sub("[REDACTED_AWS_KEY]", out)
    out = SECRET_VALUE_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", out)
    if len(out) > 160:
        out = out[:157] + "..."
    return out


def redact_args(args: dict[str, Any]) -> dict[str, Any]:
    data = copy.deepcopy(args or {})

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            return redact(v)
        if isinstance(v, dict):
            return {k: walk(val) for k, val in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, tuple):
            return tuple(walk(x) for x in v)
        return v

    return walk(data)


@dataclass(slots=True)
class Action:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    agent_id: str = "main-agent"
    action_type: str = "tool_call"  # tool_call | message
    source_context: str = "untrusted"  # trusted | untrusted
    trace_id: str = field(default_factory=_short_trace)
    raw_output: str = ""

    def text_blob(self) -> str:
        parts: list[str] = []
        if self.raw_output:
            parts.append(self.raw_output)
        parts.extend(_flatten(self.args))
        return "\n".join(p for p in parts if p)

