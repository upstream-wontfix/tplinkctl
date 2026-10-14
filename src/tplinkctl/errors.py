# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Amol Venkataraman
"""Turn raw router/library/network errors into one-line explanations.

The underlying library reports failures as long strings that embed Python dicts,
encrypted response bodies and LuCI stack messages. `explain()` recognises the
common cases and says what happened and what to do; anything unrecognised is
trimmed to its first meaningful line. The raw text stays available on
RouterError.raw (shown with --debug).
"""
from __future__ import annotations

import re

import requests

LIB_PREFIX_RE = re.compile(r"^(?:[A-Za-z0-9_]+ - )+")
FAILURE_COUNT_RE = re.compile(r"['\"]failureCount['\"]:\s*(\d+)")
ATTEMPTS_LEFT_RE = re.compile(r"['\"]attemptsAllowed['\"]:\s*(\d+)")
MAX_LEN = 240


def _first_line(text: str) -> str:
    text = LIB_PREFIX_RE.sub("", text.strip())
    line = text.splitlines()[0] if text else "unknown error"
    return line if len(line) <= MAX_LEN else line[: MAX_LEN - 1] + "…"


def explain(exc: BaseException, *, host: str | None = None, path: str | None = None,
            op: str | None = None) -> str:
    """Return a short, actionable description of `exc`."""
    where = host or "the router"

    # Network-level failures (requests exceptions; order matters: subclasses first).
    if isinstance(exc, requests.exceptions.SSLError):
        return f"TLS certificate check failed for {where}; routers use self-signed certificates, so retry with --insecure"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return f"timed out connecting to {where}; check the address and that this machine is on the router's network"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return f"{where} accepted the connection but didn't answer in time; it may be busy or rebooting (try --timeout 60)"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return f"cannot connect to {where}; check the address and that the router is reachable"

    text = str(exc)
    lower = text.lower()

    # Login failures: TP-Link counts wrong passwords and locks the login after the limit.
    if "attemptsallowed" in lower or "login failed" in lower or "cannot authorize" in lower:
        failures, left = FAILURE_COUNT_RE.search(text), ATTEMPTS_LEFT_RE.search(text)
        if left and int(left.group(1)) == 0:
            return ("login is locked after too many wrong passwords; wait for the lockout to expire "
                    "(or reboot the router) before trying again")
        if left:
            count = f"{failures.group(1)} failed attempt(s), " if failures else ""
            return (f"wrong password for {where} ({count}{left.group(1)} attempt(s) left before the router "
                    "locks logins); fix the password file before retrying")
        return f"login to {where} failed; check the username and password"
    if "conflict" in lower and ("user" in lower or "login" in lower):
        return "another admin session blocked the login; close the router's web UI and retry"

    # Endpoint-level failures.
    if "no root node was registered" in lower or "luci-mod-admin-full" in lower:
        return f"unknown endpoint {path!r} on this router; run `tplink endpoints` to list valid ones"
    if "no such callback" in lower:
        return f"{path!r} does not support operation {op!r}" if op else f"{path!r} does not support that operation"
    if "permission denied" in lower or "unauthorized" in lower or "'timeout'" in lower:
        return "the router rejected the session (expired, or another login took over); run the command again"
    if "expecting value" in lower or "unknown response" in lower:
        return f"unexpected response from the router for {path!r}" if path else "unexpected response from the router"

    return _first_line(text)
