# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Amol Venkataraman
"""`tplink` command-line interface. Run `tplink --help`."""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import logging
import os
import sys
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Any

import requests

from . import __version__
from .config import (
    CONFIG_FILE,
    DEFAULT_PASSWORD_FILE,
    ConfigError,
    resolve_host,
    resolve_settings,
    write_password_file,
)
from .diagnose import collect, diagnose
from .endpoints import discover_endpoints
from .errors import explain
from .router import WIFI_BANDS, Router, RouterError

GLOBAL_DEFAULTS: dict[str, Any] = {
    "host": None, "username": None, "password_file": None, "timeout": None,
    "insecure": False, "json": False, "debug": False, "config": str(CONFIG_FILE),
}
SEVERITY_MARK = {"error": "✖", "warn": "!", "info": "i", "ok": "✓"}
MAX_CELL = 48
WIFI_KEYS = ["ssid", "enable", "hidden", "encryption", "psk_version", "psk_key",
             "channel", "current_channel", "htmode", "hwmode", "txpower"]
DISCLAIMER_SHORT = ("Provided AS IS, without warranty of any kind, under the GNU GPL v3 or later. "
                    "Written with AI assistance: review the code before running it. See DISCLAIMER.md.")


# --------------------------------------------------------------------------- output

def print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def print_table(rows: list[dict[str, Any]], columns: list[str] | None = None) -> None:
    if not rows:
        print("(none)")
        return
    columns = columns or list(dict.fromkeys(k for row in rows for k in row))

    def cell(value: Any) -> str:
        text = "" if value is None else str(value)
        return text if len(text) <= MAX_CELL else text[: MAX_CELL - 1] + "…"

    table = [[cell(row.get(c)) for c in columns] for row in rows]
    widths = [max(len(c), *(len(r[i]) for r in table)) for i, c in enumerate(columns)]
    print("  ".join(c.upper().ljust(w) for c, w in zip(columns, widths, strict=True)).rstrip())
    for r in table:
        print("  ".join(v.ljust(w) for v, w in zip(r, widths, strict=True)).rstrip())


def print_mapping(obj: dict[str, Any]) -> None:
    width = max((len(k) for k in obj), default=0)
    for k, v in obj.items():
        print(f"{k.ljust(width)}  {v}")


def emit(obj: Any, as_json: bool, columns: list[str] | None = None) -> None:
    if as_json:
        print_json(obj)
    elif isinstance(obj, list):
        print_table(obj, columns)
    elif isinstance(obj, dict):
        print_mapping(obj)
    else:
        print(obj)


def parse_params(pairs: list[str]) -> dict[str, str]:
    params = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise ValueError(f"parameter {pair!r} must look like key=value")
        params[key] = value
    return params


def ip_sort_key(value: str) -> tuple[int, int]:
    try:
        return (0, int(ipaddress.IPv4Address(value)))
    except ValueError:
        return (1, 0)


# --------------------------------------------------------------------------- commands

def cmd_info(r: Router, a: argparse.Namespace) -> int:
    emit({"client_type": r.client_type, **r.firmware()}, a.json)
    return 0


def cmd_status(r: Router, a: argparse.Namespace) -> int:
    status = r.status()
    devices = status.pop("devices", [])
    if a.json:
        print_json({**status, "devices_total": len(devices)})
    else:
        print_mapping({k: v for k, v in status.items() if v is not None})
    return 0


def cmd_devices(r: Router, a: argparse.Namespace) -> int:
    columns = ["hostname", "ipaddr", "macaddr", "type", "signal", "down_speed", "up_speed", "online_time"]
    emit(r.devices(), a.json, columns)
    return 0


def cmd_leases(r: Router, a: argparse.Namespace) -> int:
    emit(r.leases(), a.json, ["hostname", "ipaddr", "macaddr", "lease_time"])
    return 0


def cmd_reservations(r: Router, a: argparse.Namespace) -> int:
    emit(r.reservations(), a.json, ["hostname", "ipaddr", "macaddr", "enabled"])
    return 0


def cmd_arp(r: Router, a: argparse.Namespace) -> int:
    arp = r.arp()
    if not a.by_mac:
        emit(arp, a.json, ["ipaddr", "mac", "name"])
        return 0
    groups: dict[str, list[str]] = defaultdict(list)
    for entry in arp:
        groups[entry.get("mac", "?")].append(entry.get("ipaddr", "?"))
    rows = [{"mac": mac, "count": len(ips), "ips": " ".join(sorted(ips, key=ip_sort_key))}
            for mac, ips in sorted(groups.items(), key=lambda kv: -len(kv[1]))]
    if a.json:
        print_json(rows)
    else:
        for row in rows:
            print(f"{row['mac']}  {row['count']:>4}  {row['ips']}")
    return 0


def cmd_wifi(r: Router, a: argparse.Namespace) -> int:
    wifi = r.wifi(show_secrets=a.show_secrets)
    for band in wifi.get("ignored_bands", []):
        print(f"note: the router returned placeholder settings for band {band} but has no such radio; ignored",
              file=sys.stderr)
    if a.json:
        print_json(wifi)
        return 0
    for name, cfg in wifi.items():
        if name == "ignored_bands":
            continue
        print(f"[{name}]")
        print_mapping({k: cfg[k] for k in WIFI_KEYS if k in cfg} if name in WIFI_BANDS else cfg)
        print()
    return 0


def cmd_logs(r: Router, a: argparse.Namespace) -> int:
    logs = r.logs()
    if a.type:
        logs = [e for e in logs if str(e.get("type", "")).upper() == a.type.upper()]
    if a.level:
        logs = [e for e in logs if str(e.get("level", "")).upper() == a.level.upper()]
    if a.grep:
        logs = [e for e in logs if a.grep.lower() in str(e.get("content", "")).lower()]
    logs = logs[: a.limit] if a.limit else logs
    if a.json:
        print_json(logs)
    else:
        for e in logs:
            print(f"{e.get('time')}  {e.get('level')!s:<7} {e.get('type')!s:<16} {e.get('content')}")
    return 0


def _print_findings(findings, as_json: bool, show_ok: bool) -> None:
    if as_json:
        print_json([f.to_dict() for f in findings])
        return
    for f in findings:
        if f.severity == "ok" and not show_ok:
            continue
        print(f"{SEVERITY_MARK.get(f.severity, '?')} [{f.severity}] {f.title}")
        if f.detail:
            print(f"    {f.detail}")
    counts = {s: sum(f.severity == s for f in findings) for s in ("error", "warn", "info", "ok")}
    print(f"\n{counts['error']} error(s), {counts['warn']} warning(s), {counts['info']} note(s), {counts['ok']} passed")


def cmd_diagnose(r: Router | None, a: argparse.Namespace) -> int:
    if a.from_file:
        snapshot = json.loads(Path(a.from_file).read_text())
    else:
        snapshot = collect(r, probe_dns=a.probe_dns)
        if a.save:
            Path(a.save).write_text(json.dumps(snapshot, indent=2, default=str))
            print(f"snapshot saved to {a.save}", file=sys.stderr)
    findings = diagnose(snapshot, hoard_threshold=a.hoard_threshold)
    _print_findings(findings, a.json, a.verbose)
    return 1 if any(f.severity == "error" for f in findings) else 0


def cmd_snapshot(r: Router, a: argparse.Namespace) -> int:
    text = json.dumps(collect(r, probe_dns=a.probe_dns), indent=2, default=str)
    if a.output:
        Path(a.output).write_text(text)
        print(f"snapshot saved to {a.output}", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_read(r: Router, a: argparse.Namespace) -> int:
    result = r.request(a.path, a.op, a.param_dict) if a.op else r.read(a.path, a.param_dict)
    print_json(result)
    return 0


def cmd_write(r: Router, a: argparse.Namespace) -> int:
    if not a.yes:
        print(f"About to send operation={a.op} to {a.path} with {a.param_dict or 'no parameters'}.")
        if input("This changes router settings. Type 'yes' to continue: ").strip().lower() != "yes":
            print("aborted")
            return 1
    print_json(r.request(a.path, a.op, a.param_dict, allow_write=True))
    return 0


# --------------------------------------------------------------------------- parser

def _add_global_options(p: argparse.ArgumentParser) -> None:
    S = argparse.SUPPRESS  # so options work both before and after the subcommand
    g = p.add_argument_group("connection/output")
    g.add_argument("--host", default=S, help="router URL or IP (default: config, $TPLINK_HOST, http://192.168.0.1)")
    g.add_argument("--username", default=S, help="admin username (default: admin)")
    g.add_argument("--password-file", default=S,
                   help="file whose first line is the password (default: ~/.config/tplinkctl/password)")
    g.add_argument("--timeout", type=int, default=S, help="request timeout in seconds (default: 30)")
    g.add_argument("--insecure", action="store_true", default=S, help="don't verify HTTPS certificates")
    g.add_argument("--config", default=S, help="config file (default: ~/.config/tplinkctl/config.ini)")
    g.add_argument("--json", action="store_true", default=S, help="machine-readable JSON output")
    g.add_argument("--debug", action="store_true", default=S, help="log HTTP-level details and raw errors to stderr")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tplink",
        description="Read-first CLI for TP-Link routers. Nothing is changed unless you use `write`.",
        epilog=textwrap.fill("Password: put it in ~/.config/tplinkctl/password (run `tplink set-password`) "
                             "or set $TPLINK_PASSWORD.") + "\n\n" + textwrap.fill(DISCLAIMER_SHORT),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}\n{textwrap.fill(DISCLAIMER_SHORT)}")
    _add_global_options(parser)
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add(name: str, func, help_text: str, login: bool = True) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        _add_global_options(p)
        p.set_defaults(func=func, login=login)
        return p

    add("info", cmd_info, "model, firmware and detected client type")
    add("status", cmd_status, "WAN/LAN/Wi-Fi status summary")
    add("devices", cmd_devices, "connected clients")
    add("leases", cmd_leases, "DHCP leases")
    add("reservations", cmd_reservations, "DHCP address reservations")

    p = add("arp", cmd_arp, "router ARP table (which MAC answers for which IP)")
    p.add_argument("--by-mac", action="store_true", help="group IPs by MAC (spots devices claiming many IPs)")

    p = add("wifi", cmd_wifi, "Wi-Fi settings per band (passwords redacted)")
    p.add_argument("--show-secrets", action="store_true", help="include Wi-Fi passwords")

    p = add("logs", cmd_logs, "router system log")
    p.add_argument("-n", "--limit", type=int, default=50, help="max entries, newest first (0 = all; default 50)")
    p.add_argument("--type", help="only this log type, e.g. DHCPC, NAT")
    p.add_argument("--level", help="only this level, e.g. WARNING")
    p.add_argument("--grep", help="only entries containing this text")

    p = add("diagnose", cmd_diagnose, "check for common reasons devices can't connect")
    p.add_argument("--from", dest="from_file", metavar="FILE", help="diagnose a saved snapshot instead of the live router")
    p.add_argument("--save", metavar="FILE", help="also save the collected snapshot as JSON")
    p.add_argument("--probe-dns", action="store_true", help="test the DNS servers DHCP hands out (from this machine)")
    p.add_argument("--hoard-threshold", type=int, default=3, help="flag a MAC answering for this many IPs (default 3)")
    p.add_argument("-v", "--verbose", action="store_true", help="also show passed checks")

    p = add("snapshot", cmd_snapshot, "dump everything diagnose reads as JSON (secrets redacted)")
    p.add_argument("-o", "--output", metavar="FILE", help="write to FILE instead of stdout")
    p.add_argument("--probe-dns", action="store_true", help="include a DNS reachability probe")

    p = add("read", cmd_read, "read any endpoint, e.g. 'admin/dhcps?form=setting' (see `endpoints`)")
    p.add_argument("path")
    p.add_argument("params", nargs="*", metavar="key=value", help="extra request parameters")
    p.add_argument("--op", choices=["read", "load"], help="operation (default: try read, then load)")

    p = add("write", cmd_write, "send a state-changing operation to an endpoint (asks for confirmation)")
    p.add_argument("path")
    p.add_argument("params", nargs="*", metavar="key=value", help="request parameters")
    p.add_argument("--op", required=True, help="operation, e.g. write, insert, remove")
    p.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")

    p = add("endpoints", None, "list endpoints found in the router's web UI (no login)", login=False)
    p.add_argument("--grep", help="only endpoints containing this text")

    p = add("set-password", None, "save the router password to the password file (mode 600)", login=False)
    p.add_argument("--file", default=str(DEFAULT_PASSWORD_FILE),
                   help="where to store it (default: ~/.config/tplinkctl/password)")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate everything that can be checked before logging in.

    Logging in kicks other admin sessions and counts toward the router's
    lockout, so bad input is rejected first.
    """
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    # argparse can't take positionals after options (`write PATH --op write a=1`), so
    # trailing key=value tokens are folded into params for read/write.
    if extra and getattr(args, "params", None) is not None and all("=" in x and not x.startswith("-") for x in extra):
        args.params += extra
    elif extra:
        parser.error(f"unrecognized arguments: {' '.join(extra)}")
    for name, default in GLOBAL_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, default)
    if getattr(args, "params", None) is not None:
        try:
            args.param_dict = parse_params(args.params)
        except ValueError as e:
            parser.error(str(e))
    if args.command == "write" and not args.yes and not sys.stdin.isatty():
        parser.error("refusing to write without --yes when not running interactively")
    return args


def _run(args: argparse.Namespace, logger: logging.Logger | None) -> int:
    if args.command == "set-password":
        first = getpass.getpass("Router admin password: ")
        if not first or first != getpass.getpass("Again: "):
            print("error: passwords empty or did not match", file=sys.stderr)
            return 2
        print(f"saved to {write_password_file(first, args.file)}")
        return 0

    if args.command == "endpoints":
        host = resolve_host(args.host, args.config)
        try:
            found = discover_endpoints(host, timeout=args.timeout or 10, verify_ssl=not args.insecure)
        except requests.RequestException as e:
            raise RouterError(explain(e, host=host), e) from e
        if args.grep:
            found = [e for e in found if args.grep in e]
        if args.json:
            print_json(found)
        else:
            print("\n".join(found) or "(none found)")
        return 0

    if args.command == "diagnose" and args.from_file:
        return cmd_diagnose(None, args)

    settings = resolve_settings(args.host, args.username, args.password_file, args.timeout,
                                args.insecure, args.config)
    with Router.from_settings(settings, logger) as router:
        return args.func(router, args)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    logger = logging.getLogger("tplinkctl") if args.debug else None
    try:
        code = _run(args, logger)
        sys.stdout.flush()  # surface a closed pipe here rather than during interpreter shutdown
        return code
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except RouterError as e:
        print(f"error: {e}", file=sys.stderr)
        if args.debug and e.raw is not None:
            print(f"raw error: {e.raw!r}", file=sys.stderr)
        return 1
    except BrokenPipeError:  # output piped into e.g. `head`, which exited early
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        if args.debug:
            raise
        print(f"error: {type(e).__name__}: {e} (re-run with --debug for details)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
