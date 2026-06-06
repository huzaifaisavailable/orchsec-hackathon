# OrchSec

Runtime output-layer firewall for AI agents. OrchSec intercepts each proposed tool call or final message, evaluates deterministic policies plus heuristics, optionally escalates ambiguous sensitive cases to an LLM judge, and returns one of:

- `ALLOW`
- `BLOCK`
- `REQUIRE_APPROVAL`
- `REDACT`
- `LOG_ONLY`

If the decision is not `ALLOW`, the dangerous action does not execute.

## Why this exists

Agents can be manipulated by untrusted content (for example indirect prompt injection in emails or documents). OrchSec assumes compromise and enforces policy at the final action gate before real-world effect.

## Architecture

1. Normalize an action into a common object.
2. Run deterministic policy matcher (`policies/default.yml`) and heuristics.
3. If deterministic `BLOCK` fires, return immediately.
4. Optionally run LLM judge for ambiguous sensitive paths.
5. Judge can escalate to `BLOCK`, never downgrade deterministic `BLOCK`.
6. Write redacted JSONL audit record.

## Project layout

```
orchsec/
  __init__.py
  action.py
  detectors.py
  judge.py
  engine.py
  wrapper.py
policies/
  default.yml
demo.py
integrate_dvea.py
requirements.txt
tests/test_orchsec.py
```

## Install

```bash
python -m pip install -r requirements.txt
```

## Run demo

```bash
python demo.py
```

Expected output order:

1. `BLOCK`
2. `ALLOW`
3. `BLOCK`

The audit file `audit.log.jsonl` is written with redacted fields.

## Optional LLM judge

The judge talks to the **Qwen** API through its OpenAI-compatible endpoint.

Set the key (any of these env vars works, checked in this order):

```bash
export QWEN_API_KEY=your_key_here
# or DASHSCOPE_API_KEY, or the legacy OPENAI_API_KEY
```

Defaults:

- model: `qwen3.6-flash`
- base URL: `https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1`

You can override the model/base URL via `OrchSec(..., judge_model=..., judge_base_url=...)` for any OpenAI-compatible provider.

## Integrating with vulnerable email agent (DVEA)

Reference adapter examples are in `integrate_dvea.py`:

- Wrap plain function tool.
- Wrap LangChain-style tool `.func`.

This keeps agent logic unchanged while enforcing runtime action policy.

## Tests

```bash
python -m pytest -q
```

Coverage includes:

- external + sensitive send blocks
- internal benign send allows
- external attachment requires approval
- dangerous shell command blocks
- message encoded URL exfil blocks
- base64-hidden secret blocks after normalization
- lookalike domain parsing
- deterministic block cannot be overridden by judge

