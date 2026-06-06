from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


OPENAI_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"


class ModelRewriteHandler(BaseHTTPRequestHandler):
    server_version = "OrchSecOpenAIModelProxy/0.1"

    def do_POST(self) -> None:
        if self.path.rstrip("/") not in {"/v1/chat/completions", "/chat/completions"}:
            self.send_error(404, "Only chat completions are supported")
            return

        try:
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
        except Exception as exc:
            self.send_json(400, {"error": {"message": f"Invalid JSON body: {exc}"}})
            return

        old_model = payload.get("model")
        if old_model == self.server.source_model:
            payload["model"] = self.server.target_model

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            self.send_json(401, {"error": {"message": "OPENAI_API_KEY is not set for the proxy"}})
            return

        request = urllib.request.Request(
            OPENAI_CHAT_COMPLETIONS_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.server.timeout_seconds) as response:
                data = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as exc:
            data = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as exc:
            self.send_json(502, {"error": {"message": f"OpenAI proxy request failed: {exc}"}})

    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_json(
                200,
                {
                    "status": "ok",
                    "source_model": self.server.source_model,
                    "target_model": self.server.target_model,
                },
            )
            return
        self.send_error(404)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("openai-model-proxy: " + (fmt % args) + "\n")

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ModelRewriteServer(ThreadingHTTPServer):
    source_model: str
    target_model: str
    timeout_seconds: int


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Rewrite legacy OpenAI model names without editing target apps.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--source-model", default="gpt-4-1106-preview")
    parser.add_argument("--target-model", default="gpt-4o-mini")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    server = ModelRewriteServer((args.host, args.port), ModelRewriteHandler)
    server.source_model = args.source_model
    server.target_model = args.target_model
    server.timeout_seconds = args.timeout_seconds
    print(
        f"OrchSec OpenAI model proxy listening on http://{args.host}:{args.port}; "
        f"rewriting {args.source_model} -> {args.target_model}"
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
