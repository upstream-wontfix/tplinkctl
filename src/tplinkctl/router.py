# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Amol Venkataraman
"""Session wrapper around tplinkrouterc6u with plain-data results and a write guard.

Every method returns JSON-serialisable data (dicts, lists, str, int, ...).
Anything other than a read is refused unless `allow_write=True` is passed.
"""
from __future__ import annotations

import contextlib
import logging
import socket
from enum import Enum
from typing import Any
from urllib.parse import urlencode, urlsplit

import requests
from tplinkrouterc6u import TplinkRouterProvider
from tplinkrouterc6u.common.exception import ClientException

from .config import Settings
from .errors import explain

READ_OPS = frozenset({"read", "load"})
SECRET_KEYS = frozenset({
    "psk_key", "wpa_key", "wep_key1", "wep_key2", "wep_key3", "wep_key4",
    "password", "passwd", "pwd", "token", "stok",
})
REDACTED = "<redacted>"
REACHABILITY_TIMEOUT = 5  # seconds; the library otherwise probes ~20 router types in turn

# Well-known endpoints of the LuCI-style web UI (Archer AX/C series, newer firmware).
EP_DHCP_SETTINGS = "admin/dhcps?form=setting"
EP_LAN = "admin/network?form=lan_ipv4"
EP_ARP = "admin/imb?form=arp_list"
EP_IMB = "admin/imb?form=setting"
EP_LOGS = "admin/syslog?form=log"
EP_ACCESS_ENABLE = "admin/access_control?form=enable"
EP_ACCESS_MODE = "admin/access_control?form=mode"
EP_ACCESS_BLACK = "admin/access_control?form=black_list"
EP_ACCESS_WHITE = "admin/access_control?form=white_list"
EP_PARENTAL = "admin/parental_control?form=enable"
EP_WIFI_SCHEDULE = "admin/wireless_schedule_v2?form=settings"
EP_WIFI_BAND = "admin/wireless?form=wireless_{band}"
EP_WIFI_GUEST = "admin/wireless?form=guest"
EP_SMART_CONNECT = "admin/wireless?form=smart_connect"
WIFI_BANDS = ("2g", "5g", "6g")


class RouterError(Exception):
    """A router request failed. `str(e)` is a short explanation; `e.raw` is the original error."""

    def __init__(self, message: str, raw: BaseException | None = None):
        super().__init__(message)
        self.raw = raw


class WriteNotAllowed(RouterError):
    """A non-read operation was attempted without allow_write=True."""


class UnsupportedOperation(RouterError):
    """The detected client type does not support this call."""


def to_plain(obj: Any) -> Any:
    """Convert library objects (dataclasses, enums, IP/MAC types) to plain data."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_plain(v) for v in obj]
    if type(obj).__module__.startswith("tplinkrouterc6u") and hasattr(obj, "__dict__"):
        return {k.lstrip("_"): to_plain(v) for k, v in vars(obj).items()}
    return str(obj)  # IPv4Address, EUI48, datetime, ...


def redact(obj: Any) -> Any:
    """Return a copy of `obj` with values of secret-looking keys replaced."""
    if isinstance(obj, dict):
        return {k: (REDACTED if k.lower() in SECRET_KEYS and v not in ("", None) else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def check_reachable(host: str, timeout: float = REACHABILITY_TIMEOUT) -> None:
    """Fail fast with a clear message if nothing accepts TCP connections at `host`."""
    url = urlsplit(host)
    port = url.port or (443 if url.scheme == "https" else 80)
    try:
        with socket.create_connection((url.hostname, port), timeout=timeout):
            pass
    except OSError as e:
        reason = "timed out" if isinstance(e, socket.timeout) else (e.strerror or str(e))
        raise RouterError(
            f"cannot reach {url.hostname}:{port} ({reason}); check the address and that this machine "
            "is on the router's network", e) from e


def unsupported_bands(status: dict[str, Any]) -> set[str]:
    """Bands the status reports as absent (None), e.g. 6 GHz on a dual-band router.

    Only trusted when the status reports at least one band, since some client
    types leave every band field unset.
    """
    flags = {band: status.get(f"wifi_{band}_enable") for band in WIFI_BANDS}
    if all(v is None for v in flags.values()):
        return set()
    return {band for band, v in flags.items() if v is None}


class Router:
    """A logged-in session. Use as a context manager so the session is released:

        with Router.from_settings(resolve_settings()) as r:
            print(r.devices())

    TP-Link routers allow one admin session at a time, so opening this logs out
    anyone using the web UI. Each failed login counts toward the router's lockout.
    """

    def __init__(self, host: str, password: str, username: str = "admin", *,
                 timeout: int = 30, verify_ssl: bool = True, logger: logging.Logger | None = None):
        self._host = host
        self._password = password
        self._username = username
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._logger = logger
        self._client = None

    @classmethod
    def from_settings(cls, settings: Settings, logger: logging.Logger | None = None) -> Router:
        return cls(settings.host, settings.password, settings.username,
                   timeout=settings.timeout, verify_ssl=settings.verify_ssl, logger=logger)

    # -- session -----------------------------------------------------------
    def open(self) -> Router:
        check_reachable(self._host, min(self._timeout, REACHABILITY_TIMEOUT))
        try:
            client = TplinkRouterProvider.get_client(self._host, self._password, self._username,
                                                     self._logger, self._verify_ssl, self._timeout)
            client.authorize()
        except (ClientException, requests.RequestException) as e:
            raise RouterError(explain(e, host=self._host), e) from e
        self._client = client
        return self

    def close(self) -> None:
        if self._client is not None:
            with contextlib.suppress(Exception):  # best effort; the session also expires on its own
                self._client.logout()
            self._client = None

    def __enter__(self) -> Router:  # noqa: PYI034 -- Self needs typing_extensions on 3.10
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def client(self):
        if self._client is None:
            raise RouterError("not logged in; use `with Router(...)` or call open()")
        return self._client

    @property
    def client_type(self) -> str:
        return type(self.client).__name__

    @property
    def supports_raw(self) -> bool:
        return hasattr(self.client, "request")

    # -- typed reads (work on every client type the library supports) -------
    def _call(self, method: str) -> Any:
        fn = getattr(self.client, method, None)
        if fn is None:
            raise UnsupportedOperation(f"{self.client_type} does not support {method}()")
        try:
            return to_plain(fn())
        except (ClientException, requests.RequestException) as e:
            raise RouterError(f"{method}: {explain(e, host=self._host)}", e) from e

    def firmware(self) -> dict:
        return self._call("get_firmware")

    def status(self) -> dict:
        """Router status including a `devices` list of connected clients."""
        return self._call("get_status")

    def devices(self) -> list[dict]:
        return self.status()["devices"]

    def ipv4_status(self) -> dict:
        return self._call("get_ipv4_status")

    def leases(self) -> list[dict]:
        return self._call("get_ipv4_dhcp_leases")

    def reservations(self) -> list[dict]:
        return self._call("get_ipv4_reservations")

    # -- raw endpoint access (LuCI-style web UIs) ----------------------------
    def request(self, path: str, op: str = "read", params: dict[str, Any] | None = None, *,
                allow_write: bool = False) -> Any:
        """Send `operation=<op>` (plus params) to an endpoint like 'admin/dhcps?form=setting'."""
        if op not in READ_OPS and not allow_write:
            raise WriteNotAllowed(f"operation {op!r} on {path} changes router state; pass allow_write=True")
        if not self.supports_raw:
            raise UnsupportedOperation(f"{self.client_type} does not support raw endpoint requests")
        data = urlencode({"operation": op, **(params or {})})
        try:
            return self.client.request(path, data)
        except (ClientException, requests.RequestException) as e:
            raise RouterError(explain(e, host=self._host, path=path, op=op), e) from e

    def read(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Read an endpoint, trying operation=read then operation=load."""
        errors: list[RouterError] = []
        for op in ("read", "load"):
            try:
                return self.request(path, op, params)
            except UnsupportedOperation:
                raise
            except RouterError as e:
                errors.append(e)
        messages = list(dict.fromkeys(str(e) for e in errors))  # unknown endpoints fail identically
        if all("does not support operation" in m for m in messages):
            messages = [f"{path!r} supports neither 'read' nor 'load'; see `tplink endpoints` or try `--op`"]
        raise RouterError("; ".join(messages), errors[-1].raw)

    # -- convenience reads ---------------------------------------------------
    def dhcp_settings(self) -> dict:
        return self.read(EP_DHCP_SETTINGS)

    def arp(self) -> list[dict]:
        return self.read(EP_ARP) or []

    def logs(self) -> list[dict]:
        return self.request(EP_LOGS, "load") or []

    def wifi(self, show_secrets: bool = False) -> dict[str, Any]:
        """Settings per band plus guest/smart-connect.

        Bands the router can't read are omitted. Some dual-band routers still
        return a placeholder 6 GHz config; bands the status reports as absent are
        dropped and listed under `ignored_bands` instead.
        """
        try:
            absent = unsupported_bands(self.status())
        except RouterError:
            absent = set()
        result: dict[str, Any] = {}
        ignored: list[str] = []
        for band in WIFI_BANDS:
            try:
                cfg = self.read(EP_WIFI_BAND.format(band=band))
            except RouterError:
                continue
            if band in absent:
                ignored.append(band)
            else:
                result[band] = cfg
        for name, path in (("guest", EP_WIFI_GUEST), ("smart_connect", EP_SMART_CONNECT)):
            with contextlib.suppress(RouterError):
                result[name] = self.read(path)
        if ignored:
            result["ignored_bands"] = ignored
        return result if show_secrets else redact(result)
