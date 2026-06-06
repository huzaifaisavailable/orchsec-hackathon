"""Integration guide for wrapping Damn Vulnerable Email Agent tools with OrchSec.

This file is intentionally instructional for hackathon demos.
"""

from orchsec import OrchSec, protect_tool


def integration_examples() -> None:
    """Reference-only examples for two common tool shapes."""

    orchsec = OrchSec("policies/default.yml")

    # Shape A: plain function
    # import tools
    # tools.send_email = protect_tool(orchsec, "send_email")(tools.send_email)

    # Shape B: LangChain Tool object with .func
    # send_tool.func = protect_tool(orchsec, "send_email")(send_tool.func)

    # Preserve normal agent behavior:
    # - ALLOW: wrapped function executes as usual.
    # - BLOCK/REQUIRE_APPROVAL: function is not executed; safe error string returned.


if __name__ == "__main__":
    integration_examples()

