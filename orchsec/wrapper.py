from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from .action import Action, get_recipients
from .engine import ALLOW, Decision, OrchSec


def render(action: Action, decision: Decision) -> None:
    recipient = ", ".join(get_recipients(action.args)[:3]) or "-"
    text = (
        f"[{decision.decision}] severity={decision.severity} judged_by={decision.judged_by} "
        f"tool={action.tool} recipient={recipient} policy={decision.policy_id or '-'} "
        f"trace={decision.trace_id} reason={decision.reason}"
    )

    try:
        from rich.console import Console
        from rich.panel import Panel

        color = {
            "ALLOW": "green",
            "BLOCK": "red",
            "REQUIRE_APPROVAL": "yellow",
            "REDACT": "cyan",
            "LOG_ONLY": "blue",
        }.get(decision.decision, "white")
        Console().print(Panel(text, title="OrchSec", border_style=color))
    except Exception:
        print(text)


def protect_tool(
    orchsec: OrchSec,
    tool_name: str,
    source_context: str = "untrusted",
    verbose: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            action = Action(
                tool=tool_name,
                args=dict(kwargs),
                source_context=source_context,
                action_type="tool_call",
            )
            decision = orchsec.evaluate(action)
            if verbose:
                render(action, decision)

            if decision.decision == ALLOW:
                return fn(*args, **kwargs)

            return (
                f"OrchSec blocked action {action.tool}: {decision.decision}. "
                f"Reason: {decision.reason}. trace_id={decision.trace_id}"
            )

        return wrapped

    return decorator

