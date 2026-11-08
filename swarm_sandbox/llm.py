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


def _key() -> str:
    key = os.environ.get("ADAPTION_API_KEY")
    if not key:
        raise RuntimeError(
            "ADAPTION_API_KEY is not set. Set it in the environment; never pass "
            "it as an argument or write it into a file the agent can read."
        )
    return key


def redact(text: str) -> str:
    """Remove the API key from text before it is logged or displayed."""
    if not text:
        return text
    key = os.environ.get("ADAPTION_API_KEY")
    if key and key in text:
        text = text.replace(key, "[REDACTED_API_KEY]")
    return text


def validate_tools(tools: list[dict[str, Any]]) -> None:
    """Refuse any tool that is not one of our own local function tools."""
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
        headers = {"Authorization": f"Bearer {_key()}"}

        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                r = httpx.post(ADAPTION_URL, json=body, headers=headers, timeout=self.timeout)
            except httpx.HTTPError as e:
                last_err = e
                time.sleep(2 ** attempt)
                continue
            if r.status_code == 200:
                return self._parse(r.json())
            if r.status_code in (429, 502, 503) and attempt < self.max_retries:
                time.sleep(2 ** attempt)
                continue
            # Redact the response text in case it echoes anything sensitive.
            raise RuntimeError(f"Adaption HTTP {r.status_code}: {redact(r.text)[:300]}")
        raise RuntimeError(f"Adaption request failed after retries: {last_err}")

    def _parse(self, d: dict[str, Any]) -> ModelReply:
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
        charged = self.budget.charge(
            cost=u.get("cost"), input_tokens=in_tok, output_tokens=out_tok
        )
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
