"""Start the OrchSec web dashboard."""

from __future__ import annotations

import argparse

import uvicorn

from dashboard.app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="OrchSec Dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--policy", default="policies/default.yml")
    parser.add_argument("--audit", default="audit.log.jsonl")
    parser.add_argument("--use-judge", action="store_true")
    args = parser.parse_args()

    app = create_app(
        policy_path=args.policy,
        audit_path=args.audit,
        use_judge=args.use_judge,
    )
    print(f"OrchSec Dashboard → http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
