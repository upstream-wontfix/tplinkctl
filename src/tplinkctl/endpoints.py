# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Amol Venkataraman
"""Discover the router's settings endpoints by crawling its web UI JavaScript.

Needs no login: the UI bundle is public. Works for the Vite-built web UI used by
recent Archer firmware (/webpages/index.html + /webpages/js/*-<hash>.js).
"""
from __future__ import annotations

import re
from collections import deque

import requests

ENDPOINT_RE = re.compile(r"admin/[a-z0-9_]+\?form=[a-z0-9_]+")
ENTRY_RE = re.compile(r'src="\.?/?js/([^"?]+\.js)')
CHUNK_RE = re.compile(r"""["'/]([A-Za-z0-9_.-]+-[0-9a-f]{8}\.js)""")


def discover_endpoints(host: str, timeout: float = 10, max_files: int = 500,
                       verify_ssl: bool = True) -> list[str]:
    """Return every `admin/<module>?form=<form>` path referenced by the web UI."""
    session = requests.Session()
    session.verify = verify_ssl
    index = session.get(f"{host}/webpages/index.html", timeout=timeout)
    index.raise_for_status()

    queue = deque(ENTRY_RE.findall(index.text))
    seen = set(queue)
    found: set[str] = set(ENDPOINT_RE.findall(index.text))
    fetched = 0
    while queue and fetched < max_files:
        name = queue.popleft()
        resp = session.get(f"{host}/webpages/js/{name}", timeout=timeout)
        fetched += 1
        if resp.status_code != 200:
            continue
        found.update(ENDPOINT_RE.findall(resp.text))
        for chunk in CHUNK_RE.findall(resp.text):
            if chunk not in seen:
                seen.add(chunk)
                queue.append(chunk)
    return sorted(found)
