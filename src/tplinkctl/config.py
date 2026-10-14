# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Amol Venkataraman
"""Resolve router connection settings from CLI flags, environment and config file.

Precedence (highest first): explicit arguments, environment variables, the
config file (~/.config/tplinkctl/config.ini), built-in defaults.

The password is never taken from a command-line flag (it would leak into shell
history and `ps`). It comes from, in order: TPLINK_PASSWORD, a password file
named by --password-file / TPLINK_PASSWORD_FILE / the config file, or the
default password file ~/.config/tplinkctl/password.
"""
from __future__ import annotations

import configparser
import os
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "tplinkctl"
CONFIG_FILE = CONFIG_DIR / "config.ini"
DEFAULT_PASSWORD_FILE = CONFIG_DIR / "password"
DEFAULT_HOST = "http://192.168.0.1"
DEFAULT_USERNAME = "admin"


class ConfigError(Exception):
    """Settings could not be resolved (missing/empty password file, bad config)."""


@dataclass(frozen=True)
class Settings:
    host: str
    username: str
    password: str
    timeout: int = 30
    verify_ssl: bool = True

    def __repr__(self) -> str:  # keep the password out of logs and tracebacks
        return (f"Settings(host={self.host!r}, username={self.username!r}, password='***', "
                f"timeout={self.timeout}, verify_ssl={self.verify_ssl})")


def normalize_host(host: str) -> str:
    host = host.strip().rstrip("/")
    return host if "://" in host else f"http://{host}"


def read_password_file(path: str | Path) -> str:
    """Return the first line of `path`, warning if other users can read it."""
    path = Path(path).expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(f"password file not found: {path} (create it with `tplink set-password`)") from None
    except OSError as e:
        raise ConfigError(f"cannot read password file {path}: {e}") from None
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(f"warning: {path} is accessible by other users; run: chmod 600 {path}", file=sys.stderr)
    lines = text.splitlines()
    password = lines[0] if lines else ""
    if not password:
        raise ConfigError(f"password file is empty: {path}")
    return password


def write_password_file(password: str, path: str | Path = DEFAULT_PASSWORD_FILE) -> Path:
    """Store `password` in `path` with mode 0600 (directory 0700)."""
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(password + "\n")
    os.chmod(path, 0o600)  # O_CREAT's mode is ignored if the file already existed
    return path


def load_config_file(path: str | Path = CONFIG_FILE) -> dict[str, str]:
    """Return the [router] section of the INI config file, or {} if absent."""
    path = Path(path).expanduser()
    if not path.exists():
        return {}
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error as e:
        raise ConfigError(f"invalid config file {path}: {e}") from None
    return dict(parser["router"]) if parser.has_section("router") else {}


def resolve_host(host: str | None = None, config_file: str | Path = CONFIG_FILE,
                 env: Mapping[str, str] = os.environ) -> str:
    """Resolve only the host (for commands that don't log in)."""
    return normalize_host(host or env.get("TPLINK_HOST") or load_config_file(config_file).get("host") or DEFAULT_HOST)


def resolve_settings(
    host: str | None = None,
    username: str | None = None,
    password_file: str | Path | None = None,
    timeout: int | None = None,
    insecure: bool = False,
    config_file: str | Path = CONFIG_FILE,
    env: Mapping[str, str] = os.environ,
) -> Settings:
    cfg = load_config_file(config_file)

    host = resolve_host(host, config_file, env)
    username = username or env.get("TPLINK_USERNAME") or cfg.get("username") or DEFAULT_USERNAME

    if password_file is None and env.get("TPLINK_PASSWORD"):
        password = env["TPLINK_PASSWORD"]
    else:
        source = password_file or env.get("TPLINK_PASSWORD_FILE") or cfg.get("password_file") or DEFAULT_PASSWORD_FILE
        password = read_password_file(source)

    if timeout is None:
        try:
            timeout = int(env.get("TPLINK_TIMEOUT") or cfg.get("timeout") or 30)
        except ValueError:
            raise ConfigError("timeout must be an integer number of seconds") from None

    verify_ssl = not insecure and cfg.get("verify_ssl", "true").strip().lower() not in {"0", "false", "no", "off"}
    return Settings(host, username, password, timeout, verify_ssl)
