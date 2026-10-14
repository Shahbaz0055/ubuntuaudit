# ubuntuaudit
Python command line tool that audits Ubuntu systems for security problems and suggests fixes

# UbuntuAudit

A small command line tool that checks an Ubuntu system for common security problems and prints a clear report with fix suggestions.

## Checks

* Pending security updates through apt
* Automatic security updates (unattended upgrades)
* SSH server settings: root login, empty passwords, password login
* Services listening beyond localhost
* Firewall status (ufw)

## Install

    git clone https://github.com/<your-user>/ubuntuaudit
    cd ubuntuaudit
    pip install .

## Usage

    ubuntuaudit
    sudo ubuntuaudit
    ubuntuaudit --only ssh ports
    ubuntuaudit --no-color

Run with sudo to see process names for listening ports and the firewall status.

Exit status is 1 when any check fails and 0 otherwise so it works in scripts and CI.

## Example output

    [FAIL] Security updates: 3 security updates pending
           Fix: sudo apt update && sudo apt upgrade
    [PASS] Automatic security updates: Unattended upgrades is enabled
    [WARN] SSH password login: Password login is allowed
           Fix: Use keys and set 'PasswordAuthentication no'

    Security score: 62/100

## Development

    pip install pytest
    pytest

## Roadmap

* Debian package and snap
* Man page
* More checks: sudo configuration, file permissions, kernel hardening settings

## License

GPL 3.0 or later

