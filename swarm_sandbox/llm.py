"""Model client for the broker.

Security rules enforced here:
  * The API key is read ONLY from the ADAPTION_API_KEY environment variable.
    It is never taken from an argument, a file, or anything an agent can set.
  * The key is never printed, logged, or returned. `redact()` scrubs it from
    any text before that text is written to a log.
  * A hard spend limit stops the run if exceeded. The limit is a single
    RunBudget SHARED across every agent in the run, so the ceiling is the whole
    run's spend, not per-agent (N agents x cap).
  * The budget fails CLOSED: if the provider response carries no usable cost
    field, spend is estimated from token counts; if even those are missing, the
    call is still counted against a request ceiling, so a mis-shaped response
    can never make the limit silently unreachable.
  * Only our own `function` tools are ever sent. Server-side tools that could
    act outside our sandbox (remote MCP, hosted file_search, web search,
    code execution) are refused before the request leaves this process.

The model only ever returns TEXT and `function_call` items. It cannot execute
anything. Whether a requested command runs is decided by the broker, and it
runs inside the locked agent container, never here.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

# ---- HOW TO READ THIS FILE ----
# Purpose: the ONLY place the broker talks to the model provider. It enforces
# three trust boundaries before any request leaves this process.
# Map:
#   * _key / redact: the API key is read only from ADAPTION_API_KEY (never an
#     argument or file an agent could set) and is scrubbed from any text we log.
#   * validate_tools + _FORBIDDEN_TOOL_TYPES: only our own local "function" tools
#     are sent; provider-side tools (mcp, web_search, code_interpreter, ...) that
#     could act outside our sandbox are refused.
#   * RunBudget: one spend ceiling shared across the WHOLE run; .check() before a
#     request, .charge() after. charge() FAILS CLOSED (see below).
#   * AdaptionClient.respond / _parse: builds the request (store:false), retries
#     transient errors, and reads back only text + function_call items.
# Invariant: the model returns data, never actions -- it cannot execute anything;
# whether a command runs is the broker's decision, inside the locked container.

ADAPTION_URL = "https://api.prod.adaptionlabs.ai/api/v1/responses"

# Tool `type` values that execute on the provider side and could reach outside
# our sandbox. We refuse to send any of these.
_FORBIDDEN_TOOL_TYPES = {
    "mcp",
    "remote_mcp",
    "file_search",
    "web_search",
    "web_search_preview",
    "code_interpreter",
    "code_execution",
    "computer",
    "computer_use_preview",
    "connector",
}

# Fallback price when the provider returns no `cost`: credits per 1M tokens.
# Deliberately conservative (over-estimates) so the cap trips early, never late.
_FALLBACK_CREDITS_PER_MTOK = 1.0


class SpendCapExceeded(RuntimeError):
    """Raised when a run has spent more than its credit cap (or request ceiling)."""


class UnsafeToolError(ValueError):
    """Raised when a tool definition would run outside our sandbox."""


# ---- key handling and tool allowlist (the trust boundaries) ----

def _key() -> str:
    # The key comes ONLY from the environment. Taking it from an argument or a
    # file would let an agent that can influence those inputs steer our spend or
    # swap in its own key; env-only keeps it on the broker's side of the boundary.
    key = os.environ.get("ADAPTION_API_KEY")
    if not key:
        raise RuntimeError(
            "ADAPTION_API_KEY is not set. Set it in the environment; never pass "
            "it as an argument or write it into a file the agent can read."
        )
    return key


def redact(text: str) -> str:
    """Remove the API key from text before it is logged or displayed."""
    # Last line of defence: even if the key is echoed back in a provider error or
    # tool output, this strips it before the text reaches the log or a display.
    if not text:
        return text
    key = os.environ.get("ADAPTION_API_KEY")
    if key and key in text:
        text = text.replace(key, "[REDACTED_API_KEY]")
    return text


def validate_tools(tools: list[dict[str, Any]]) -> None:
    """Refuse any tool that is not one of our own local function tools."""
    # Allowlist, not blocklist: anything that is not a local "function" tool is
    # rejected. Provider-side tools (web_search, code_interpreter, mcp, ...) would
    # execute outside our sandbox where nothing is logged or contained, so they
    # must never be sent -- failing the request is the safe outcome.
    for t in tools:
        ttype = t.get("type")
        if ttype in _FORBIDDEN_TOOL_TYPES:
            raise UnsafeToolError(f"Refusing provider-side tool {ttype!r}.")
        if ttype != "function":
            raise UnsafeToolError(
                f"Refusing tool of type {ttype!r}: only local 'function' tools "
                "are allowed, so nothing runs outside our sandbox."
            )


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    credits: float = 0.0


# ---- the shared, fail-closed spend budget ----

class RunBudget:
    """A single spend ceiling shared by every agent in a run.

    Checked before each request and updated after. Because one object is shared,
    the ceiling applies to the whole run, not to each agent separately.
    """

    def __init__(self, cap_credits: float = 5.0, max_requests: int = 2000) -> None:
        self.cap_credits = cap_credits
        self.max_requests = max_requests
        self.total = Usage()
        self.requests = 0
        self.cost_missing = False  # set if the provider ever omitted a usable cost

    def check(self) -> None:
        # Two independent stops: credit spend AND a raw request count. The request
        # ceiling is a backstop so the run still halts even if cost accounting is
        # broken or every response reports zero cost.
        if self.total.credits >= self.cap_credits:
            raise SpendCapExceeded(
                f"Run spent {self.total.credits:.4f} >= cap {self.cap_credits} credits."
            )
        if self.requests >= self.max_requests:
            raise SpendCapExceeded(
                f"Run hit the request ceiling ({self.max_requests} requests)."
            )

    def charge(self, *, cost: Any, input_tokens: int, output_tokens: int) -> float:
        """Record one response. Returns the credits charged for it.

        If `cost` is a usable number, it is used. Otherwise spend is estimated
        from tokens and a warning is emitted once, so a missing/renamed cost
        field degrades to a conservative estimate instead of counting as free.
        """
        # Count the request first: even a response we can't price still advances
        # the request ceiling, so a mis-shaped response can't be "free" forever.
        self.requests += 1
        self.total.input_tokens += int(input_tokens)
        self.total.output_tokens += int(output_tokens)
        try:
            credits = float(cost)
            usable = credits >= 0.0
        except (TypeError, ValueError):
            usable = False
            credits = 0.0
        if not usable:
            # Fail closed: no usable provider cost -> estimate from tokens with a
            # deliberately high rate, so a renamed/absent 'cost' field over-charges
            # (cap trips early) rather than counting as zero (cap never reached).
            tok = int(input_tokens) + int(output_tokens)
            credits = tok / 1_000_000.0 * _FALLBACK_CREDITS_PER_MTOK
            if not self.cost_missing:
                self.cost_missing = True
                print(
                    "[budget] WARNING: provider response had no usable 'cost'; "
                    f"estimating spend from tokens (~{_FALLBACK_CREDITS_PER_MTOK}"
                    " credits/Mtok). The cap still applies.",
                    file=sys.stderr,
                )
        self.total.credits += credits
        return credits


@dataclass
class ModelReply:
    """What the broker gets back for one turn."""

    text: str
    tool_calls: list[dict[str, Any]]  # each: {call_id, name, arguments(str)}
    raw_output: list[dict[str, Any]]  # provider `output` items, for replay/history
    response_id: str | None
    served_model: str
    usage: Usage
    cost_estimated: bool = False      # True if spend was estimated, not provider-reported


class LLMClient:
    """Base class. Subclasses implement `respond`."""

    name = "base"

    def respond(
        self,
        *,
        instructions: str,
        input_items: list[dict[str, Any]] | str,
        tools: list[dict[str, Any]],
        temperature: float = 0.0,
        max_output_tokens: int = 1024,
    ) -> ModelReply:
        raise NotImplementedError


class AdaptionClient(LLMClient):
    """Calls Adaption's Responses API. Enforces the shared budget and tool allowlist."""

    def __init__(
        self,
        model: str,
        *,
        budget: RunBudget | None = None,
        spend_cap_credits: float = 5.0,
        timeout: float = 90.0,
        max_retries: int = 2,
    ) -> None:
        self.model = model
        self.name = f"adaption:{model}"
        # One budget per run; if none is passed, make a private one (solo use).
        self.budget = budget if budget is not None else RunBudget(spend_cap_credits)
        self.timeout = timeout
        self.max_retries = max_retries

    @property
    def total(self) -> Usage:  # backwards-compatible view
        return self.budget.total

    def respond(
        self,
        *,
        instructions: str,
        input_items: list[dict[str, Any]] | str,
        tools: list[dict[str, Any]],
        temperature: float = 0.0,
        max_output_tokens: int = 1024,
    ) -> ModelReply:
        # Order matters: reject unsafe tools and confirm we're under budget BEFORE
        # we build a request or spend anything.
        validate_tools(tools)
        self.budget.check()

        body = {
            "model": self.model,
            "store": False,  # Adaption keeps nothing; we hold the only transcript
            "temperature": temperature,
            "max_output_tokens": max_output_tokens,
            "instructions": instructions,
            "input": input_items,
            "tools": tools,
        }
        headers = {"Authorization": f"Bearer {_key()}"}  # key fetched here, never stored on the object

        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                r = httpx.post(ADAPTION_URL, json=body, headers=headers, timeout=self.timeout)
            except httpx.HTTPError as e:
                last_err = e
                time.sleep(2 ** attempt)  # exponential backoff on transport errors
                continue
            if r.status_code == 200:
                return self._parse(r.json())
            if r.status_code in (429, 502, 503) and attempt < self.max_retries:
                time.sleep(2 ** attempt)  # retry only transient rate-limit / gateway errors
                continue
            # Redact the response text in case it echoes anything sensitive.
            raise RuntimeError(f"Adaption HTTP {r.status_code}: {redact(r.text)[:300]}")
        raise RuntimeError(f"Adaption request failed after retries: {last_err}")

    def _parse(self, d: dict[str, Any]) -> ModelReply:
        # Read back ONLY two kinds of item: text messages and function_call
        # requests. The model proposes a command; it never runs one. Nothing in
        # this response is executed here -- the broker decides, in the container.
        output = d.get("output", []) or []
        tool_calls: list[dict[str, Any]] = []
        text_parts: list[str] = []
        for item in output:
            itype = item.get("type")
            if itype == "function_call":
                tool_calls.append(
                    {
                        "call_id": item.get("call_id"),
                        "name": item.get("name"),
                        "arguments": item.get("arguments", "{}"),
                    }
                )
            elif itype == "message":
                # Responses wire format: text lives in content parts of type output_text.
                for part in item.get("content", []) or []:
                    if part.get("type") == "output_text" and part.get("text"):
                        text_parts.append(part["text"])

        # Prefer the SDK-style aggregate when present (Adaption returns it), else
        # fall back to the text we reconstructed from output[] message items.
        text = d.get("output_text")
        if not text:
            text = "".join(text_parts)

        u = d.get("usage", {}) or {}
        in_tok = int(u.get("input_tokens", 0) or 0)
        out_tok = int(u.get("output_tokens", 0) or 0)
        before = self.budget.cost_missing
        # Charge the shared budget now, so this request's spend is on the books
        # before the broker acts on the reply (the next check() sees it).
        charged = self.budget.charge(
            cost=u.get("cost"), input_tokens=in_tok, output_tokens=out_tok
        )
        # Flag that THIS reply's cost was estimated (provider sent no usable cost),
        # so callers/logs can tell reported spend from estimated spend.
        estimated = self.budget.cost_missing and ("cost" not in u or u.get("cost") is None)
        return ModelReply(
            text=text or "",
            tool_calls=tool_calls,
            raw_output=output,
            response_id=d.get("id"),
            served_model=d.get("model", self.model),
            usage=Usage(in_tok, out_tok, charged),
            cost_estimated=estimated,
        )
