# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Amol Venkataraman
"""Collect a read-only snapshot of the router and check it for common problems.

`collect()` talks to the router; `diagnose()` is a pure function over the
snapshot, so a saved snapshot can be re-checked offline and in tests.
"""
from __future__ import annotations

import ipaddress
import random
import socket
import struct
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from . import router as R
from .router import Router, RouterError, redact

SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2, "ok": 3}


@dataclass(frozen=True)
class Finding:
    severity: str  # error | warn | info | ok
    code: str
    title: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


# --------------------------------------------------------------------------- collect

def collect(router: Router, probe_dns: bool = False) -> dict[str, Any]:
    """Read everything the checks need. Failures are recorded, not raised."""
    sources: dict[str, Callable[[], Any]] = {
        "firmware": router.firmware,
        "status": router.status,
        "leases": router.leases,
        "reservations": router.reservations,
        "dhcp_settings": router.dhcp_settings,
        "lan": lambda: router.read(R.EP_LAN),
        "arp": router.arp,
        "wifi": router.wifi,
        "access_control": lambda: {
            "enable": router.read(R.EP_ACCESS_ENABLE),
            "mode": router.read(R.EP_ACCESS_MODE),
        },
        "access_control_black": lambda: router.read(R.EP_ACCESS_BLACK),
        "access_control_white": lambda: router.read(R.EP_ACCESS_WHITE),
        "parental_control": lambda: router.read(R.EP_PARENTAL),
        "wireless_schedule": lambda: router.read(R.EP_WIFI_SCHEDULE),
        "ip_mac_binding": lambda: router.read(R.EP_IMB),
        "logs": router.logs,
    }
    data: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name, fn in sources.items():
        try:
            data[name] = fn()
        except Exception as e:  # noqa: BLE001 -- network errors and odd responses surface as findings, not crashes
            errors[name] = str(e) if isinstance(e, RouterError) else f"{type(e).__name__}: {e}"

    if probe_dns:
        servers = [s for s in _dns_servers(data) if s]
        data["dns_probe"] = {s: probe_dns_server(s) for s in servers}

    return redact({
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "client_type": router.client_type,
        "data": data,
        "errors": errors,
    })


def probe_dns_server(server: str, name: str = "example.com", timeout: float = 2.0) -> str | None:
    """Send one A query over UDP. Returns None on success, else an error string."""
    qid = random.randint(0, 0xFFFF)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    packet = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, (server, 53))
            reply, _ = s.recvfrom(4096)
        except OSError as e:
            return f"no reply ({e.__class__.__name__}: {e})" if str(e) else f"no reply ({e.__class__.__name__})"
    if len(reply) < 12 or struct.unpack(">H", reply[:2])[0] != qid:
        return "malformed reply"
    rcode = reply[3] & 0x0F
    return None if rcode == 0 else f"server returned rcode {rcode}"


# --------------------------------------------------------------------------- helpers

def _mac(value: Any) -> str:
    return str(value or "").upper().replace(":", "-")


def _ip(value: Any) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(str(value))
    except ValueError:
        return None


def _dns_servers(data: dict[str, Any]) -> list[str]:
    dhcp = data.get("dhcp_settings") or {}
    return [dhcp.get("pri_dns", ""), dhcp.get("snd_dns", "")]


def _device_names(data: dict[str, Any]) -> dict[str, str]:
    names: dict[str, str] = {}
    for d in (data.get("status") or {}).get("devices", []) + (data.get("leases") or []):
        mac, host = _mac(d.get("macaddr")), d.get("hostname") or ""
        if host and host not in ("--", "network device"):
            names.setdefault(mac, host)
    return names


def _sample(items: list[Any], n: int = 8) -> str:
    shown = ", ".join(str(i) for i in items[:n])
    return shown + (f", ... (+{len(items) - n} more)" if len(items) > n else "")


# --------------------------------------------------------------------------- checks

def check_wan(data: dict[str, Any], **_: Any) -> list[Finding]:
    status = data.get("status")
    if not status:
        return []
    wan = _ip(status.get("wan_ipv4_addr"))
    if wan is None or wan.is_unspecified:
        return [Finding("error", "wan-down", "Router has no WAN (internet) IPv4 address")]
    return [Finding("ok", "wan-up", f"WAN is up ({wan})")]


def check_dhcp_enabled(data: dict[str, Any], **_: Any) -> list[Finding]:
    dhcp = data.get("dhcp_settings")
    if dhcp is None:
        return []
    if str(dhcp.get("enable", "on")).lower() != "on":
        return [Finding("error", "dhcp-off", "DHCP server is disabled",
                        "Devices that expect an automatic address cannot get one.")]
    return []


def check_arp_hoarding(data: dict[str, Any], hoard_threshold: int = 3, **_: Any) -> list[Finding]:
    arp = data.get("arp")
    if arp is None:
        return []
    by_mac: dict[str, set[ipaddress.IPv4Address]] = defaultdict(set)
    for entry in arp:
        ip = _ip(entry.get("ipaddr"))
        if ip:
            by_mac[_mac(entry.get("mac"))].add(ip)
    names = _device_names(data)
    hoarders = sorted(((m, ips) for m, ips in by_mac.items() if len(ips) >= hoard_threshold),
                      key=lambda x: -len(x[1]))
    if not hoarders:
        return [Finding("ok", "arp-clean", "No device answers for multiple IP addresses")]
    total = len(set().union(*(ips for _, ips in hoarders)))
    out = [Finding(
        "error", "arp-hoarding",
        f"{len(hoarders)} device(s) answer for {total} IP addresses between them",
        "New devices probe their DHCP address before using it; when another machine answers, "
        "they reject it and fail to connect. Common causes: a DHCP client that never drops old "
        "leases, proxy ARP, or an 'any-IP' local route on a server/container.")]
    for mac, ips in hoarders:
        label = f"{mac} ({names[mac]})" if mac in names else mac
        out.append(Finding("error", "arp-hoarder", f"{label} claims {len(ips)} IPs",
                           _sample([str(i) for i in sorted(ips)])))
    return out


def check_address_conflicts(data: dict[str, Any], **_: Any) -> list[Finding]:
    leases, arp = data.get("leases"), data.get("arp")
    if leases is None or arp is None:
        return []
    arp_macs: dict[str, set[str]] = defaultdict(set)
    for entry in arp:
        arp_macs[str(entry.get("ipaddr"))].add(_mac(entry.get("mac")))
    out = []
    for lease in leases:
        ip, mac = str(lease.get("ipaddr")), _mac(lease.get("macaddr"))
        others = arp_macs.get(ip, set()) - {mac}
        if others:
            out.append(Finding(
                "error", "ip-conflict",
                f"{ip} is leased to {mac} ({lease.get('hostname') or '?'}) but answered by {', '.join(sorted(others))}",
                "That device will see its address as already in use."))
    return out


def check_dhcp_pool(data: dict[str, Any], **_: Any) -> list[Finding]:
    dhcp = data.get("dhcp_settings")
    if not dhcp:
        return []
    start, end = _ip(dhcp.get("ipaddr_start")), _ip(dhcp.get("ipaddr_end"))
    if not start or not end or end < start:
        return []
    size = int(end) - int(start) + 1

    def in_pool(ip: ipaddress.IPv4Address | None) -> bool:
        return ip is not None and start <= ip <= end

    leased = {ip for lease in data.get("leases") or [] if in_pool(ip := _ip(lease.get("ipaddr")))}
    reserved = {ip for r in data.get("reservations") or [] if in_pool(ip := _ip(r.get("ipaddr")))}
    in_use = {ip for e in data.get("arp") or [] if in_pool(ip := _ip(e.get("ipaddr")))}
    occupied = leased | reserved | in_use
    free = size - len(occupied)
    detail = (f"pool {start}-{end} ({size} addresses): {len(leased)} leased, {len(reserved)} reserved, "
              f"{len(in_use)} seen in ARP, {free} free")

    out = []
    if free <= size * 0.10:
        out.append(Finding("error", "dhcp-pool-exhausted", f"DHCP pool is effectively full ({free} of {size} free)", detail))
    elif free <= size * 0.25:
        out.append(Finding("warn", "dhcp-pool-low", f"DHCP pool is running low ({free} of {size} free)", detail))
    else:
        out.append(Finding("ok", "dhcp-pool", f"DHCP pool has room ({free} of {size} free)", detail))

    unleased = sorted(in_use - leased - reserved)
    if unleased:
        out.append(Finding(
            "info", "dhcp-pool-static",
            f"{len(unleased)} address(es) inside the DHCP pool are used without a lease",
            "Static IPs inside the pool can collide with addresses the router hands out; "
            f"move them outside {start}-{end} or reserve them. {_sample([str(i) for i in unleased])}"))
    return out


def check_access_control(data: dict[str, Any], **_: Any) -> list[Finding]:
    ac = data.get("access_control")
    if not ac:
        return []
    if str((ac.get("enable") or {}).get("enable", "off")).lower() != "on":
        return [Finding("ok", "access-control-off", "Access Control (block/allow list) is off")]
    mode = (ac.get("mode") or {}).get("access_mode", "?")
    if mode == "white":
        allowed = data.get("access_control_white") or []
        return [Finding("error", "access-control-allowlist",
                        f"Access Control allowlist is ON: only {len(allowed)} listed device(s) may connect",
                        "Any device not on the list (new laptops/phones, randomised MACs) is blocked.")]
    blocked = data.get("access_control_black") or []
    names = ", ".join(f"{b.get('name') or '?'} ({_mac(b.get('mac'))})" for b in blocked[:10])
    return [Finding("warn", "access-control-blocklist",
                    f"Access Control blocklist is ON with {len(blocked)} device(s) blocked", names)]


def check_parental_control(data: dict[str, Any], **_: Any) -> list[Finding]:
    pc = data.get("parental_control")
    if not pc:
        return []
    count = int(pc.get("devNum") or 0)
    if count:
        return [Finding("warn", "parental-control",
                        f"{count} device(s) are under Parental Controls",
                        "They may be blocked by time limits, bedtime or content filters.")]
    return []


def check_wireless_schedule(data: dict[str, Any], **_: Any) -> list[Finding]:
    ws = data.get("wireless_schedule")
    if ws and ws.get("enable") in (True, "on", "true"):
        rules = ws.get("list") or {}
        return [Finding("warn", "wifi-schedule",
                        f"Wi-Fi schedule is enabled ({len(rules)} rule(s)): radios turn off at set times")]
    return []


def check_ip_mac_binding(data: dict[str, Any], **_: Any) -> list[Finding]:
    imb = data.get("ip_mac_binding")
    if imb and str(imb.get("enable", "off")).lower() == "on":
        return [Finding("info", "ip-mac-binding", "IP-MAC binding is on",
                        "Devices whose IP/MAC pair does not match a binding may be dropped.")]
    return []


BAND_LABELS = {"2g": "2.4 GHz", "5g": "5 GHz", "6g": "6 GHz"}


def check_wifi(data: dict[str, Any], **_: Any) -> list[Finding]:
    wifi = data.get("wifi") or {}
    out = [Finding("info", "wifi-band-ignored",
                   f"Router returned {BAND_LABELS.get(band, band)} settings but reports no {BAND_LABELS.get(band, band)} radio",
                   "Treated as placeholder data from the firmware and ignored; it is not a disabled band.")
           for band in wifi.get("ignored_bands", [])]
    for band in R.WIFI_BANDS:
        cfg = wifi.get(band)
        if not cfg:
            continue
        label = BAND_LABELS[band]
        if str(cfg.get("enable", "on")).lower() != "on" or str(cfg.get("disabled", "off")).lower() == "on":
            out.append(Finding("warn", "wifi-band-off", f"{label} Wi-Fi is disabled"))
            continue
        if cfg.get("hidden") == "on":
            out.append(Finding("info", "wifi-hidden", f"{label} SSID {cfg.get('ssid')!r} is hidden"))
        psk_version = cfg.get("psk_version")
        if psk_version == "sae":
            out.append(Finding("warn", "wifi-wpa3-only", f"{label} is WPA3-only",
                               "Many older laptops/phones cannot join WPA3-only networks."))
        elif psk_version == "sae_transition":
            out.append(Finding("info", "wifi-wpa2-wpa3", f"{label} uses WPA2/WPA3 mixed mode",
                               "Some older Windows Wi-Fi drivers fail to join mixed mode; "
                               "if one device can't connect, try a driver update or WPA2-only."))
    return out


def check_dns(data: dict[str, Any], **_: Any) -> list[Finding]:
    dhcp = data.get("dhcp_settings")
    lan = data.get("lan") or {}
    if not dhcp:
        return []
    out = []
    router_ip = _ip(lan.get("ipaddr"))
    mask = lan.get("mask_type") or "255.255.255.0"
    subnet = ipaddress.IPv4Network(f"{router_ip}/{mask}", strict=False) if router_ip else None
    for server in filter(None, _dns_servers(data)):
        ip = _ip(server)
        if ip and subnet and ip in subnet and ip != router_ip:
            out.append(Finding("info", "dns-local",
                               f"DHCP hands out {server} (a LAN host) as DNS",
                               "If that host is down or filtering, clients get 'connected, no internet'."))
    for server, err in (data.get("dns_probe") or {}).items():
        if err:
            out.append(Finding("error", "dns-unreachable", f"DNS server {server} did not answer", err))
        else:
            out.append(Finding("ok", "dns-reachable", f"DNS server {server} answers"))
    return out


def check_logs(data: dict[str, Any], **_: Any) -> list[Finding]:
    logs = data.get("logs")
    if not logs:
        return []
    bad_levels = {"WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY"}
    bad = [entry for entry in logs if str(entry.get("level", "")).upper() in bad_levels]
    if not bad:
        return []
    recent = "; ".join(f"{e.get('time')} {e.get('type')}: {e.get('content')}" for e in bad[:5])
    return [Finding("info", "log-warnings", f"{len(bad)} warning/error entries in the router log", recent)]


CHECKS: list[Callable[..., list[Finding]]] = [
    check_wan, check_dhcp_enabled, check_arp_hoarding, check_address_conflicts, check_dhcp_pool,
    check_access_control, check_parental_control, check_wireless_schedule, check_ip_mac_binding,
    check_wifi, check_dns, check_logs,
]


def diagnose(snapshot: dict[str, Any], hoard_threshold: int = 3) -> list[Finding]:
    """Run every check against a snapshot from collect(); most severe first."""
    data = snapshot.get("data", {})
    findings: list[Finding] = []
    for check in CHECKS:
        try:
            findings.extend(check(data, hoard_threshold=hoard_threshold))
        except Exception as e:  # noqa: BLE001 -- one malformed section must not hide the other checks
            findings.append(Finding("info", "check-failed", f"{check.__name__} could not run", repr(e)))
    for name, err in (snapshot.get("errors") or {}).items():
        findings.append(Finding("info", "not-collected", f"Could not read {name}", err))
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
