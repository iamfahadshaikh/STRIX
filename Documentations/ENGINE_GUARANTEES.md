# Engine Guarantees (Backend Semantics)

This backend is in stabilization mode. Semantics are frozen unless explicitly revisited. Consumers should rely on the following contract.

## Core Guarantees
- HTTPS capability is probed once up front via TLS handshake with short timeouts; the verdict is cached and not re-inferred later. TLS tools gate on this cached result.
- Tool outcomes are canonical:
  - `SUCCESS_WITH_FINDINGS`: rc==0 (or tolerated rc like 141 for nikto) **and** positive signal.
  - `SUCCESS_NO_FINDINGS`: rc==0/141 **and** an explicit negative signal (tool confirmed absence).
  - `EXECUTED_NO_SIGNAL`: rc==0/141 with no signal (empty/none). Cannot raise confidence.
  - `TIMEOUT`: rc indicates timeout.
  - `BLOCKED`: prerequisites missing, tool unavailable, or permission denied.
  - `SKIPPED`: decision layer chose not to run (budget or no expected signal).
  - `EXECUTION_ERROR`: everything else.
- `failure_reason` is aligned with outcome (e.g., `tool_not_installed`, `permission_denied`, `target_unreachable`, `timeout`, `unknown_error`).
- Empty stdout with rc==0/141 is **not** treated as success; it is `EXECUTED_NO_SIGNAL`.
- Skipped/blocked tools are recorded in `execution_results`; no success language is used for them.
- stderr is persisted with length and truncation indicator; full stdout/stderr are written to per-tool files.

## Reporting Truths
- `execution_report.json` is the source of truth. HTML is derived but must not contradict JSON.
- Categories are descriptive for reporting/budgeting; they are **not** a capability model.
- Discovery counts (endpoints/params/reflections/subdomains/ports) come only from the discovery cache.

## Non-Goals / Explicitly Not Done
- No automatic retries/downgrades beyond configured per-tool retries.
- No adaptive category re-mapping; categories remain cosmetic if not enforced by capabilities.
- No long-term health metadata per tool (expected runtime, failure patterns) yet.
- No inference-based HTTPS enablement; if the probe fails, TLS tools are gated.

## Operational Expectations
- Use `execution_results` to understand skips/blocks/errors; do not infer success from plan membership.
- Treat `SUCCESS_NO_FINDINGS` as a negative signal only when the tool explicitly confirmed absence; otherwise expect `EXECUTED_NO_SIGNAL`.
- If HTTPS probe fails, SSL/TLS tooling will be skipped by design.
