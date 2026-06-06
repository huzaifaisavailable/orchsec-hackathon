from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

from orchsec.engine import OrchSec
from orchsec.smtp_proxy import SmtpEnvelope, evaluate_and_forward, extract_email_fields


def make_message(to_addr: str, body: str, *, subject: str = "Hello") -> bytes:
    msg = EmailMessage()
    msg["From"] = "bot@bot.com"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    return msg.as_bytes()


def make_engine(tmp_path: Path) -> OrchSec:
    return OrchSec(
        policy_path="policies/default.yml",
        audit_path=str(tmp_path / "smtp-audit.jsonl"),
        use_judge=False,
        fail_closed=True,
    )


def test_extract_email_fields_uses_smtp_envelope_recipients() -> None:
    envelope = SmtpEnvelope(
        mail_from="bot@bot.com",
        recipients=["malloy@test.com"],
        data=make_message("visible@example.com", "hello"),
    )
    message = EmailMessage()
    message["From"] = "bot@bot.com"
    message["To"] = "visible@example.com"
    message["Subject"] = "Hello"
    message.set_content("hello")

    fields = extract_email_fields(envelope, message)

    assert fields["to"] == ["malloy@test.com"]
    assert fields["subject"] == "Hello"
    assert fields["body"].strip() == "hello"


def test_smtp_proxy_forwards_allowed_internal_email(tmp_path: Path) -> None:
    forwarded: list[SmtpEnvelope] = []
    envelope = SmtpEnvelope(
        mail_from="bot@bot.com",
        recipients=["user@acme.com"],
        data=make_message("user@acme.com", "Thanks for the update."),
    )

    result = evaluate_and_forward(
        make_engine(tmp_path),
        envelope,
        forwarder=lambda env, _msg: forwarded.append(env),
    )

    assert result.forwarded is True
    assert result.smtp_code == 250
    assert result.decision == "ALLOW"
    assert forwarded == [envelope]


def test_smtp_proxy_blocks_sensitive_external_email(tmp_path: Path) -> None:
    forwarded: list[SmtpEnvelope] = []
    envelope = SmtpEnvelope(
        mail_from="bot@bot.com",
        recipients=["malloy@test.com"],
        data=make_message(
            "malloy@test.com",
            "Summary: your bank password is BankPassword123.",
            subject="Summary of Recent Emails",
        ),
    )

    result = evaluate_and_forward(
        make_engine(tmp_path),
        envelope,
        forwarder=lambda env, _msg: forwarded.append(env),
    )

    assert result.forwarded is False
    assert result.smtp_code == 550
    assert result.decision == "BLOCK"
    assert forwarded == []
