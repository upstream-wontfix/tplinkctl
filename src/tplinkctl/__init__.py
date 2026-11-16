# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Amol Venkataraman
"""Read-first CLI and Python API for TP-Link routers, built on tplinkrouterc6u.

Provided AS IS, without warranty of any kind; see LICENSE and DISCLAIMER.md.
"""
__version__ = "0.1.1"

from .config import ConfigError, Settings, resolve_settings
from .diagnose import Finding, collect, diagnose
from .router import Router, RouterError, UnsupportedOperation, WriteNotAllowed

__all__ = [
    "ConfigError",
    "Finding",
    "Router",
    "RouterError",
    "Settings",
    "UnsupportedOperation",
    "WriteNotAllowed",
    "__version__",
    "collect",
    "diagnose",
    "resolve_settings",
]
