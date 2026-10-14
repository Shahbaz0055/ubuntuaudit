"""Security checks. Every check returns a list of Result objects."""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
from dataclasses import dataclass

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"


@dataclass
class Result:
    name: str
    status: str
    message: str
    fix: str = ""


@dataclass
class Listener:
    proto: str
    address: str
    port: str
    process: str


def run(cmd, timeout=30):
    """Run a command and return the CompletedProcess or None on failure."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


# ---------------------------------------------------------------- updates


def parse_upgradable(output):
    """Return (total, security) counts from `apt list --upgradable` output."""
    lines = [
        line
        for line in output.splitlines()
        if "/" in line and not line.startswith(("Listing", "WARNING"))
    ]
    security = [line for line in lines if "-security" in line]
    return len(lines), len(security)


def check_updates():
    name = "Security updates"
    proc = run(["apt", "list", "--upgradable"])
    if proc is None or proc.returncode != 0:
        return [Result(name, SKIP, "Could not run apt")]
    total, security = parse_upgradable(proc.stdout)
    fix = "sudo apt update && sudo apt upgrade"
    if security:
        return [Result(name, FAIL, f"{security} security updates pending", fix)]
    if total:
        return [Result(name, WARN, f"{total} package updates pending", fix)]
    return [Result(name, PASS, "System is up to date")]


# ------------------------------------------------------ unattended upgrades

AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"


def parse_auto_upgrades(text):
    values = {}
    for match in re.finditer(r'APT::Periodic::(\S+)\s+"(\d+)"', text):
        values[match.group(1)] = int(match.group(2))
    return values


def check_unattended(path=AUTO_UPGRADES):
    name = "Automatic security updates"
    fix = (
        "sudo apt install unattended-upgrades && "
        "sudo dpkg-reconfigure -plow unattended-upgrades"
    )
    text = read_text(path)
    if text is None:
        return [Result(name, WARN, "Unattended upgrades is not configured", fix)]
    values = parse_auto_upgrades(text)
    if values.get("Unattended-Upgrade", 0) >= 1:
        return [Result(name, PASS, "Unattended upgrades is enabled")]
    return [Result(name, WARN, "Unattended upgrades is disabled", fix)]


# -------------------------------------------------------------------- ssh

SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_CONFIG_D = "/etc/ssh/sshd_config.d/*.conf"


def parse_sshd_config(text):
    """Parse sshd_config text. The first value for a keyword wins."""
    settings = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        key, value = parts[0].lower(), parts[1].strip().lower()
        if key == "match":
            break
        settings.setdefault(key, value)
    return settings


def evaluate_ssh(settings):
    results = []

    root = settings.get("permitrootlogin", "prohibit-password")
    if root == "yes":
        results.append(
            Result(
                "SSH root login",
                FAIL,
                "Root can log in over SSH with a password",
                "Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
            )
        )
    else:
        results.append(Result("SSH root login", PASS, f"PermitRootLogin is {root}"))

    empty = settings.get("permitemptypasswords", "no")
    if empty == "yes":
        results.append(
            Result(
                "SSH empty passwords",
                FAIL,
                "Accounts with empty passwords can log in",
                "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config",
            )
        )
    else:
        results.append(Result("SSH empty passwords", PASS, "Empty passwords refused"))

    password = settings.get("passwordauthentication", "yes")
    if password == "yes":
        results.append(
            Result(
                "SSH password login",
                WARN,
                "Password login is allowed",
                "Use keys and set 'PasswordAuthentication no'",
            )
        )
    else:
        results.append(Result("SSH password login", PASS, "Password login disabled"))

    return results


def check_ssh(main_path=SSHD_CONFIG, dropin_glob=SSHD_CONFIG_D):
    main = read_text(main_path)
    if main is None:
        return [Result("SSH server", SKIP, "sshd is not installed")]
    # Ubuntu includes the drop in directory first so those values win.
    text = ""
    for path in sorted(glob.glob(dropin_glob)):
        text += (read_text(path) or "") + "\n"
    text += main
    return evaluate_ssh(parse_sshd_config(text))


# ------------------------------------------------------------------ ports


def parse_ss(output):
    """Parse `ss -tulnpH` output into Listener objects."""
    listeners = []
    for line in output.splitlines():
        parts = line.split(None, 6)
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        extra = parts[6] if len(parts) > 6 else ""
        address, _, port = local.rpartition(":")
        match = re.search(r'\(\("([^"]+)"', extra)
        listeners.append(
            Listener(
                proto, address.strip("[]"), port, match.group(1) if match else "unknown"
            )
        )
    return listeners


def is_exposed(address):
    if address.startswith("127.") or address == "::1" or "%lo" in address:
        return False
    return True


def check_ports():
    name = "Listening ports"
    proc = run(["ss", "-tulnpH"])
    if proc is None or proc.returncode != 0:
        return [Result(name, SKIP, "Could not run ss")]
    exposed = [item for item in parse_ss(proc.stdout) if is_exposed(item.address)]
    if not exposed:
        return [Result(name, PASS, "No services exposed beyond localhost")]
    shown = ", ".join(
        f"{item.port}/{item.proto} ({item.process})" for item in exposed[:8]
    )
    more = f" and {len(exposed) - 8} more" if len(exposed) > 8 else ""
    return [
        Result(
            name,
            WARN,
            f"{len(exposed)} exposed: {shown}{more}",
            "Stop services you do not need or bind them to 127.0.0.1",
        )
    ]


# --------------------------------------------------------------- firewall


def check_firewall():
    name = "Firewall"
    if shutil.which("ufw") is None:
        return [
            Result(name, WARN, "ufw is not installed", "sudo apt install ufw")
        ]
    if os.geteuid() != 0:
        return [Result(name, SKIP, "Run with sudo to read firewall status")]
    proc = run(["ufw", "status"])
    if proc is None:
        return [Result(name, SKIP, "Could not run ufw")]
    if "Status: active" in proc.stdout:
        return [Result(name, PASS, "ufw is active")]
    return [Result(name, WARN, "ufw is inactive", "sudo ufw enable")]


CHECKS = {
    "updates": check_updates,
    "unattended": check_unattended,
    "ssh": check_ssh,
    "ports": check_ports,
    "firewall": check_firewall,
}
