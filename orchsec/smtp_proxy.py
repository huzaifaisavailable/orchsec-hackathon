from __future__ import annotations

import argparse
import asyncio
import smtplib
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from pathlib import Path
from typing import Callable

from .action import Action
from .engine import ALLOW, OrchSec


SMTP_LINE_LIMIT = 1000


@dataclass(slots=True)
class SmtpEnvelope:
    mail_from: str = ""
    recipients: list[str] = field(default_factory=list)
    data: bytes = b""


@dataclass(slots=True)
class ProxyResult:
    forwarded: bool
    smtp_code: int
    message: str
    decision: str
    trace_id: str


Forwarder = Callable[[SmtpEnvelope, Message], None]


def _extract_address(command_arg: str) -> str:
    text = command_arg.strip()
    if ":" in text:
        text = text.split(":", 1)[1].strip()
    if text.startswith("<") and ">" in text:
        return text[1 : text.index(">")]
    return text.split()[0] if text else ""


def _decode_payload(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    return payload.decode(charset, errors="replace")


def extract_email_fields(envelope: SmtpEnvelope, message: Message) -> dict[str, object]:
    bodies: list[str] = []
    attachments: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            disposition = (part.get_content_disposition() or "").lower()
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
            if disposition == "attachment":
                continue
            if part.get_content_type() == "text/plain":
                bodies.append(_decode_payload(part))
    else:
        bodies.append(_decode_payload(message))

    to_values = envelope.recipients or message.get_all("to", [])
    cc_values = message.get_all("cc", [])
    bcc_values = message.get_all("bcc", [])

    return {
        "from": envelope.mail_from or message.get("from", ""),
        "to": to_values,
        "cc": cc_values,
        "bcc": bcc_values,
        "subject": message.get("subject", ""),
        "body": "\n".join(bodies),
        "attachments": attachments,
    }


def default_forwarder(host: str, port: int) -> Forwarder:
    def forward(envelope: SmtpEnvelope, message: Message) -> None:
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.sendmail(envelope.mail_from, envelope.recipients, envelope.data)

    return forward


def evaluate_and_forward(
    orchsec: OrchSec,
    envelope: SmtpEnvelope,
    *,
    forwarder: Forwarder,
    source_context: str = "untrusted",
) -> ProxyResult:
    message = BytesParser(policy=policy.default).parsebytes(envelope.data)
    fields = extract_email_fields(envelope, message)
    action = Action(
        tool="send_email",
        args=fields,
        source_context=source_context,
        action_type="tool_call",
    )
    decision = orchsec.evaluate(action)

    if decision.decision == ALLOW:
        forwarder(envelope, message)
        return ProxyResult(
            forwarded=True,
            smtp_code=250,
            message="2.0.0 OK: forwarded by OrchSec",
            decision=decision.decision,
            trace_id=decision.trace_id,
        )

    return ProxyResult(
        forwarded=False,
        smtp_code=550,
        message=(
            f"5.7.1 OrchSec blocked message: {decision.decision}. "
            f"Reason: {decision.reason}. trace_id={decision.trace_id}"
        ),
        decision=decision.decision,
        trace_id=decision.trace_id,
    )


class SmtpProxySession:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        orchsec: OrchSec,
        forwarder: Forwarder,
        source_context: str,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.orchsec = orchsec
        self.forwarder = forwarder
        self.source_context = source_context
        self.envelope = SmtpEnvelope()

    async def run(self) -> None:
        await self.reply(220, "OrchSec SMTP proxy ready")
        try:
            while not self.reader.at_eof():
                raw = await self.reader.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                command, _, arg = line.partition(" ")
                command = command.upper()

                if command in {"EHLO", "HELO"}:
                    await self.reply_multiline(
                        250,
                        [
                            "orchsec.local",
                            "AUTH PLAIN LOGIN",
                            "8BITMIME",
                            "OK",
                        ],
                    )
                elif command == "AUTH":
                    await self.handle_auth(arg)
                elif command == "MAIL":
                    self.envelope.mail_from = _extract_address(arg)
                    self.envelope.recipients.clear()
                    self.envelope.data = b""
                    await self.reply(250, "2.1.0 OK")
                elif command == "RCPT":
                    recipient = _extract_address(arg)
                    if recipient:
                        self.envelope.recipients.append(recipient)
                    await self.reply(250, "2.1.5 OK")
                elif command == "DATA":
                    await self.handle_data()
                elif command == "RSET":
                    self.envelope = SmtpEnvelope()
                    await self.reply(250, "2.0.0 OK")
                elif command == "NOOP":
                    await self.reply(250, "2.0.0 OK")
                elif command == "QUIT":
                    await self.reply(221, "2.0.0 Bye")
                    break
                else:
                    await self.reply(502, "5.5.1 Command not implemented")
        finally:
            self.writer.close()
            await self.writer.wait_closed()

    async def handle_auth(self, arg: str) -> None:
        mechanism = (arg.split()[0] if arg else "").upper()
        if mechanism == "LOGIN":
            await self.reply(334, "VXNlcm5hbWU6")
            await self.reader.readline()
            await self.reply(334, "UGFzc3dvcmQ6")
            await self.reader.readline()
        await self.reply(235, "2.7.0 Authentication accepted")

    async def handle_data(self) -> None:
        if not self.envelope.mail_from or not self.envelope.recipients:
            await self.reply(503, "5.5.1 Need MAIL and RCPT before DATA")
            return

        await self.reply(354, "End data with <CR><LF>.<CR><LF>")
        chunks: list[bytes] = []
        while True:
            line = await self.reader.readline()
            if not line:
                await self.reply(451, "4.4.2 Connection closed during DATA")
                return
            if line in {b".\r\n", b".\n"}:
                break
            if line.startswith(b".."):
                line = line[1:]
            chunks.append(line)

        self.envelope.data = b"".join(chunks)
        try:
            result = evaluate_and_forward(
                self.orchsec,
                self.envelope,
                forwarder=self.forwarder,
                source_context=self.source_context,
            )
        except Exception as exc:
            await self.reply(451, f"4.3.0 OrchSec proxy error: {exc}")
            return

        await self.reply(result.smtp_code, result.message)
        self.envelope = SmtpEnvelope()

    async def reply(self, code: int, message: str) -> None:
        self.writer.write(f"{code} {message}\r\n".encode("utf-8"))
        await self.writer.drain()

    async def reply_multiline(self, code: int, lines: list[str]) -> None:
        for line in lines[:-1]:
            self.writer.write(f"{code}-{line}\r\n".encode("utf-8"))
        self.writer.write(f"{code} {lines[-1]}\r\n".encode("utf-8"))
        await self.writer.drain()


async def serve(
    *,
    listen_host: str,
    listen_port: int,
    forward_host: str,
    forward_port: int,
    policy_path: str,
    audit_path: str,
    source_context: str,
) -> None:
    orchsec = OrchSec(policy_path=policy_path, audit_path=audit_path, use_judge=False)
    forwarder = default_forwarder(forward_host, forward_port)

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        session = SmtpProxySession(
            reader,
            writer,
            orchsec=orchsec,
            forwarder=forwarder,
            source_context=source_context,
        )
        await session.run()

    server = await asyncio.start_server(handle_client, listen_host, listen_port, limit=SMTP_LINE_LIMIT)
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(
        f"OrchSec SMTP proxy listening on {addresses}; "
        f"forwarding allowed mail to {forward_host}:{forward_port}"
    )
    async with server:
        await server.serve_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run OrchSec as an SMTP action firewall.")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=2525)
    parser.add_argument("--forward-host", default="127.0.0.1")
    parser.add_argument("--forward-port", type=int, default=2526)
    parser.add_argument("--policy-path", default=str(Path("policies") / "default.yml"))
    parser.add_argument("--audit-path", default="orchsec-proxy-audit.log.jsonl")
    parser.add_argument("--source-context", choices=["trusted", "untrusted"], default="untrusted")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    asyncio.run(
        serve(
            listen_host=args.listen_host,
            listen_port=args.listen_port,
            forward_host=args.forward_host,
            forward_port=args.forward_port,
            policy_path=args.policy_path,
            audit_path=args.audit_path,
            source_context=args.source_context,
        )
    )


if __name__ == "__main__":
    main()
