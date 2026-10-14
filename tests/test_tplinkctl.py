# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Amol Venkataraman
#
# All addresses below are documentation/example values: MACs from the IANA
# documentation block 00-00-5E-00-53-xx (RFC 7042) and WAN addresses from
# TEST-NET-3 (203.0.113.0/24, RFC 5737).
import ipaddress
import json
import os
import socket
import time
from enum import Enum

import pytest
import requests
from tplinkrouterc6u.common.exception import ClientError

from tplinkctl import __version__, cli
from tplinkctl.config import (
    ConfigError,
    read_password_file,
    resolve_settings,
    write_password_file,
)
from tplinkctl.diagnose import diagnose
from tplinkctl.errors import explain
from tplinkctl.router import (
    REDACTED,
    Router,
    RouterError,
    WriteNotAllowed,
    check_reachable,
    redact,
    to_plain,
    unsupported_bands,
)

MAC_HOARDER = "00-00-5E-00-53-01"
MAC_SERVER = "00-00-5E-00-53-02"
MAC_LAPTOP = "00-00-5E-00-53-10"
MAC_PHONE = "00-00-5E-00-53-11"
WAN_IP = "203.0.113.10"


# --------------------------------------------------------------------------- config

def test_password_file_roundtrip_is_private(tmp_path):
    path = write_password_file("p@ss word!", tmp_path / "sub" / "pw")
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert read_password_file(path) == "p@ss word!"  # inner spaces kept, newline stripped


def test_empty_or_missing_password_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        read_password_file(tmp_path / "nope")
    (tmp_path / "empty").write_text("\n")
    with pytest.raises(ConfigError, match="empty"):
        read_password_file(tmp_path / "empty")


def test_world_readable_password_file_warns(tmp_path, capsys):
    pw = tmp_path / "pw"
    pw.write_text("secret\n")
    os.chmod(pw, 0o644)
    assert read_password_file(pw) == "secret"
    assert "chmod 600" in capsys.readouterr().err


def test_settings_precedence(tmp_path):
    cfg = tmp_path / "config.ini"
    pw_cfg, pw_flag = tmp_path / "pw_cfg", tmp_path / "pw_flag"
    write_password_file("from-config-file", pw_cfg)
    write_password_file("from-flag-file", pw_flag)
    cfg.write_text(f"[router]\nhost = 10.0.0.1\nusername = root\npassword_file = {pw_cfg}\ntimeout = 5\n")

    s = resolve_settings(config_file=cfg, env={})
    assert (s.host, s.username, s.password, s.timeout) == ("http://10.0.0.1", "root", "from-config-file", 5)

    s = resolve_settings(config_file=cfg, env={"TPLINK_HOST": "https://r.lan/", "TPLINK_PASSWORD": "from-env"})
    assert (s.host, s.password) == ("https://r.lan", "from-env")

    s = resolve_settings(host="192.168.1.1", password_file=pw_flag, config_file=cfg, env={"TPLINK_PASSWORD": "from-env"})
    assert (s.host, s.password) == ("http://192.168.1.1", "from-flag-file")
    assert "from-flag-file" not in repr(s)


# --------------------------------------------------------------------------- errors

# Shapes of real library errors, with identifying values replaced.
WRONG_PASSWORD = ("TplinkRouter - TplinkRouter - Cannot authorize! Error - 'stok'; Response - {'errorcode': "
                  "'login failed', 'success': False, 'data': {'failureCount': 1, 'errorcode': '-5002', "
                  "'attemptsAllowed': 9}}")
LOCKED_OUT = WRONG_PASSWORD.replace("'failureCount': 1", "'failureCount': 10").replace("'attemptsAllowed': 9",
                                                                                        "'attemptsAllowed': 0")
UNKNOWN_ENDPOINT = ("TplinkRouter - TplinkRouter - An unknown response - Expecting value: line 1 column 1 (char 0); "
                    "Request admin/nope?form=x&operation=read - Response QUJDREVGRw== Decrypted response - No root "
                    "node was registered, this usually happens if no module was installed.\nInstall "
                    "luci-mod-admin-full and retry.")
NO_CALLBACK = ("TplinkRouter - TplinkRouter - Response with error; Request admin/a?form=b&operation=read - "
               "Response {'errorcode': 'no such callback', 'success': False}")


@pytest.mark.parametrize("raw, expected", [
    (WRONG_PASSWORD, "wrong password for http://r (1 failed attempt(s), 9 attempt(s) left"),
    (LOCKED_OUT, "login is locked after too many wrong passwords"),
    ("Login failed! Please check if your router local password is correct", "login to http://r failed"),
    (UNKNOWN_ENDPOINT, "unknown endpoint 'admin/nope?form=x'"),
    (NO_CALLBACK, "'admin/nope?form=x' does not support operation 'read'"),
])
def test_explain_client_errors(raw, expected):
    message = explain(ClientError(raw), host="http://r", path="admin/nope?form=x", op="read")
    assert expected in message
    assert "QUJDREVGRw" not in message and "{'errorcode'" not in message


@pytest.mark.parametrize("exc, expected", [
    (requests.exceptions.SSLError("bad cert"), "--insecure"),
    (requests.exceptions.ConnectTimeout("t"), "timed out connecting"),
    (requests.exceptions.ReadTimeout("t"), "didn't answer in time"),
    (requests.exceptions.ConnectionError("refused"), "cannot connect"),
])
def test_explain_network_errors(exc, expected):
    assert expected in explain(exc, host="http://r")


def test_explain_unknown_error_is_trimmed():
    message = explain(ClientError("TplinkRouter - TplinkRouter - Something odd\nsecond line " + "x" * 500))
    assert message == "Something odd"


# --------------------------------------------------------------------------- router

class Color(Enum):
    RED = "red"


def test_to_plain_and_redact():
    plain = to_plain({"ip": ipaddress.IPv4Address("10.0.0.1"), "c": Color.RED, "l": (1, None)})
    assert plain == {"ip": "10.0.0.1", "c": "red", "l": [1, None]}
    secret = {"psk_key": "hunter2", "wpa_key": "", "nested": [{"password": "x", "ssid": "Net"}]}
    assert redact(secret) == {"psk_key": REDACTED, "wpa_key": "", "nested": [{"password": REDACTED, "ssid": "Net"}]}


class FakeClient:
    """Mimics the library client: dual-band router that still returns a 6 GHz config."""

    def __init__(self):
        self.calls = []

    def get_status(self):
        return {"wifi_2g_enable": True, "wifi_5g_enable": True, "wifi_6g_enable": None, "devices": []}

    def request(self, path, data):
        self.calls.append((path, data))
        if "only_load" in path and "operation=read" in data:
            raise ClientError(NO_CALLBACK)
        if "nope" in path:
            raise ClientError(UNKNOWN_ENDPOINT)
        if "never" in path:
            raise ClientError(NO_CALLBACK)
        if "form=wireless_" in path:
            return {"ssid": "Example", "enable": "on" if "6g" not in path else "off", "psk_key": "hunter2"}
        return {"ok": True}


def make_router():
    r = Router("http://x", "pw")
    r._client = FakeClient()
    return r


def test_write_guard_blocks_non_read_ops():
    r = make_router()
    with pytest.raises(WriteNotAllowed):
        r.request("admin/x?form=y", "write", {"a": "1"})
    assert r.client.calls == []
    r.request("admin/x?form=y", "write", {"a": "1"}, allow_write=True)
    assert r.client.calls == [("admin/x?form=y", "operation=write&a=1")]


def test_read_falls_back_to_load():
    r = make_router()
    assert r.read("admin/only_load?form=z") == {"ok": True}
    assert [d for _, d in r.client.calls] == ["operation=read", "operation=load"]


def test_read_errors_are_explained_once():
    r = make_router()
    with pytest.raises(RouterError) as e:
        r.read("admin/nope?form=x")
    assert str(e.value) == "unknown endpoint 'admin/nope?form=x' on this router; run `tplink endpoints` to list valid ones"
    assert isinstance(e.value.raw, ClientError)
    with pytest.raises(RouterError, match="supports neither 'read' nor 'load'"):
        r.read("admin/never?form=x")


def test_unsupported_bands():
    assert unsupported_bands({"wifi_2g_enable": True, "wifi_5g_enable": False, "wifi_6g_enable": None}) == {"6g"}
    assert unsupported_bands({}) == set()  # client type that reports nothing: trust nothing


def test_wifi_drops_placeholder_band():
    wifi = make_router().wifi()
    assert set(wifi) >= {"2g", "5g", "ignored_bands"} and "6g" not in wifi
    assert wifi["ignored_bands"] == ["6g"]
    assert wifi["2g"]["psk_key"] == REDACTED


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_check_reachable_fails_fast_and_router_skips_login(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not try to log in to an unreachable host")
    monkeypatch.setattr("tplinkctl.router.TplinkRouterProvider.get_client", boom)
    host = f"http://127.0.0.1:{_free_port()}"
    start = time.monotonic()
    with pytest.raises(RouterError, match="cannot reach 127.0.0.1"):
        Router(host, "pw", timeout=30).open()
    assert time.monotonic() - start < 3


def test_check_reachable_ok():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        check_reachable(f"http://127.0.0.1:{server.getsockname()[1]}")


# --------------------------------------------------------------------------- cli

def test_cli_validates_before_login(monkeypatch, capsys):
    monkeypatch.setattr("tplinkctl.cli.Router.open", lambda self: pytest.fail("logged in before validating"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(SystemExit):
        cli.main(["read", "admin/x?form=y", "notkeyvalue"])
    assert "must look like key=value" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["write", "admin/x?form=y", "--op", "write", "a=1"])
    assert "--yes" in capsys.readouterr().err


def test_cli_params_after_options():
    args = cli.parse_args(["write", "admin/x?form=y", "--op", "write", "a=1", "--yes"])
    assert args.param_dict == {"a": "1"}


def test_version_and_help_carry_disclaimer(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    out = capsys.readouterr().out
    assert __version__ in out and "AS IS" in out
    assert "without warranty" in cli.build_parser().format_help()


# --------------------------------------------------------------------------- diagnose

def snapshot(**overrides):
    """A trimmed reproduction of a real failure: one host hoarding the DHCP pool."""
    arp = [{"ipaddr": f"192.168.0.{i}", "mac": MAC_HOARDER} for i in range(2, 240)]
    arp += [{"ipaddr": "192.168.0.250", "mac": MAC_SERVER}]
    data = {
        "status": {"wan_ipv4_addr": WAN_IP, "devices": [
            {"hostname": "laptop-a", "macaddr": MAC_LAPTOP, "ipaddr": "192.168.0.245"}]},
        "dhcp_settings": {"enable": "on", "ipaddr_start": "192.168.0.2", "ipaddr_end": "192.168.0.253",
                          "pri_dns": "192.168.0.250", "snd_dns": "1.1.1.1"},
        "lan": {"ipaddr": "192.168.0.1", "mask_type": "255.255.255.0"},
        "leases": [{"hostname": "phone-b", "macaddr": MAC_PHONE, "ipaddr": "192.168.0.120"},
                   {"hostname": "laptop-a", "macaddr": MAC_LAPTOP, "ipaddr": "192.168.0.245"}],
        "reservations": [],
        "arp": arp,
        "access_control": {"enable": {"enable": "off"}, "mode": {"access_mode": "black"}},
        "parental_control": {"devNum": 0},
        "wireless_schedule": {"enable": False, "list": {}},
        "wifi": {"2g": {"enable": "on", "disabled": "off", "psk_version": "sae_transition", "ssid": "Example"},
                 "ignored_bands": ["6g"]},
    }
    data.update(overrides)
    return {"data": data, "errors": {}}


def codes(findings, severity=None):
    return {f.code for f in findings if severity is None or f.severity == severity}


def test_diagnose_flags_the_real_failure():
    findings = diagnose(snapshot())
    errors = codes(findings, "error")
    assert {"arp-hoarding", "arp-hoarder", "ip-conflict", "dhcp-pool-exhausted"} <= errors
    assert "access-control-off" in codes(findings, "ok")
    assert {"dns-local", "wifi-wpa2-wpa3", "wifi-band-ignored"} <= codes(findings, "info")
    assert "wifi-band-off" not in codes(findings)  # placeholder 6 GHz is not "disabled"
    assert findings[0].severity == "error"  # sorted most severe first
    conflict = next(f for f in findings if f.code == "ip-conflict")
    assert "192.168.0.120" in conflict.title and MAC_HOARDER in conflict.title


def test_diagnose_healthy_network():
    arp = [{"ipaddr": "192.168.0.245", "mac": MAC_LAPTOP}]
    findings = diagnose(snapshot(arp=arp, leases=[{"hostname": "laptop-a", "macaddr": MAC_LAPTOP,
                                                   "ipaddr": "192.168.0.245"}]))
    assert codes(findings, "error") == set()
    assert {"arp-clean", "dhcp-pool", "wan-up"} <= codes(findings, "ok")


def test_diagnose_blocking_features():
    findings = diagnose(snapshot(
        access_control={"enable": {"enable": "on"}, "mode": {"access_mode": "white"}},
        access_control_white=[{"mac": MAC_PHONE}],
        parental_control={"devNum": 2},
        wireless_schedule={"enable": True, "list": {"r1": {}}},
        wifi={"5g": {"enable": "off"}},
    ))
    assert "access-control-allowlist" in codes(findings, "error")
    assert {"parental-control", "wifi-schedule", "wifi-band-off"} <= codes(findings, "warn")


def test_diagnose_survives_missing_and_malformed_sections():
    findings = diagnose({"data": {"arp": [{"ipaddr": "not-an-ip"}], "dhcp_settings": {"ipaddr_start": "x"}},
                         "errors": {"logs": "timeout"}})
    assert "not-collected" in codes(findings)
    assert "arp-clean" in codes(findings)


def test_cli_diagnose_from_file(tmp_path, capsys):
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(snapshot()))
    assert cli.main(["diagnose", "--from", str(snap)]) == 1
    out = capsys.readouterr().out
    assert "claims 238 IPs" in out and "error(s)" in out
    assert cli.main(["--json", "diagnose", "--from", str(snap)]) == 1
    assert any(f["code"] == "arp-hoarding" for f in json.loads(capsys.readouterr().out))
