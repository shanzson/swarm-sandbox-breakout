"""Append-only, hash-chained event log.

The log is the experiment's ground truth, so it is written ONLY by the broker,
which runs on the host, outside every agent container. Agents have no path to
it: they cannot read it, write it, or reach the directory it lives in.

Each record carries the SHA-256 of the previous record. Changing or deleting
any interior line breaks the chain from that point on. Trailing truncation
(deleting the last K records) leaves a self-consistent shorter chain, so to
detect that we also keep an out-of-band *tip anchor* -- a sidecar file holding
the record count and the final hash. `verify()` checks the chain AND, when the
anchor is present, that the log still reaches that count and tip. This mirrors
how Inspect, METR and Redwood keep the record where the agent cannot touch it.

Records are JSON lines. The API key is scrubbed from every record via
llm.redact before it is written. `verify()` never raises on a corrupt log; it
returns (False, reason) -- it is fail-closed, so a malformed record can never
be read as "intact".
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Iterator

from .llm import redact

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _scrub(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def _tip_path(path: str) -> str:
    return path + ".tip"


@dataclass
class EventLog:
    path: str
    _prev: str = GENESIS
    _seq: int = 0

    def __post_init__(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        # Resume the chain if the file already exists.
        if os.path.exists(self.path):
            for rec in self.read(self.path):
                self._prev = rec["hash"]
                self._seq = rec["seq"] + 1

    def append(self, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        body = {
            "seq": self._seq,
            "kind": kind,
            "data": _scrub(data),
            "prev": self._prev,
        }
        h = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
        rec = {**body, "hash": h}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(_canonical(rec) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._prev = h
        self._seq += 1
        # Update the out-of-band tip anchor (count + final hash) for
        # trailing-truncation detection.
        self._write_tip()
        return rec

    def _write_tip(self) -> None:
        anchor = {"count": self._seq, "tip": self._prev}
        tp = _tip_path(self.path)
        with open(tp, "w", encoding="utf-8") as f:
            f.write(_canonical(anchor) + "\n")
            f.flush()
            os.fsync(f.fileno())

    @staticmethod
    def read(path: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    @staticmethod
    def verify(path: str) -> tuple[bool, str]:
        """Return (ok, message). Fail-closed: never raises, never returns ok on
        a corrupt, malformed, or truncated log."""
        prev = GENESIS
        expected_seq = 0
        try:
            with open(path, encoding="utf-8") as f:
                for lineno, raw in enumerate(f):
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        return False, f"malformed record at line {lineno}"
                    if not isinstance(rec, dict) or not all(
                        k in rec for k in ("seq", "kind", "data", "prev", "hash")
                    ):
                        return False, f"record missing required fields at line {lineno}"
                    body = {k: rec[k] for k in ("seq", "kind", "data", "prev")}
                    h = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
                    if rec.get("seq") != expected_seq:
                        return False, f"seq gap at {rec.get('seq')} (expected {expected_seq})"
                    if rec.get("prev") != prev:
                        return False, f"broken link at seq {rec.get('seq')}"
                    if rec.get("hash") != h:
                        return False, f"hash mismatch at seq {rec.get('seq')}"
                    prev = rec["hash"]
                    expected_seq += 1
        except FileNotFoundError:
            return False, "log file not found"
        except OSError as e:
            return False, f"could not read log: {e}"

        # Check the out-of-band tip anchor, if present, to catch truncation.
        tp = _tip_path(path)
        if os.path.exists(tp):
            try:
                with open(tp, encoding="utf-8") as f:
                    anchor = json.loads(f.read().strip())
                exp_count = int(anchor["count"])
                exp_tip = str(anchor["tip"])
            except (json.JSONDecodeError, KeyError, ValueError, OSError):
                return False, "tip anchor present but unreadable"
            if expected_seq != exp_count:
                return False, (
                    f"truncation: log has {expected_seq} records, anchor expects {exp_count}"
                )
            if prev != exp_tip:
                return False, "tip hash does not match anchor"
            return True, f"chain intact: {expected_seq} records (anchor verified)"

        return True, f"chain intact: {expected_seq} records (no anchor)"

    def iter_kind(self, kind: str) -> Iterator[dict[str, Any]]:
        for rec in self.read(self.path):
            if rec["kind"] == kind:
                yield rec
