from ubuntuaudit import checks, report
from ubuntuaudit.checks import FAIL, PASS, SKIP, WARN, Result


def test_parse_upgradable_counts_security():
    output = (
        "Listing...\n"
        "openssl/jammy-security 3.0.2 amd64 [upgradable from: 3.0.1]\n"
        "vim/jammy-updates 9.0 amd64 [upgradable from: 8.2]\n"
    )
    assert checks.parse_upgradable(output) == (2, 1)


def test_parse_upgradable_empty():
    assert checks.parse_upgradable("Listing...\n") == (0, 0)


def test_parse_auto_upgrades():
    text = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
    values = checks.parse_auto_upgrades(text)
    assert values["Unattended-Upgrade"] == 1


def test_unattended_missing_file(tmp_path):
    result = checks.check_unattended(str(tmp_path / "none"))[0]
    assert result.status == WARN


def test_unattended_enabled(tmp_path):
    path = tmp_path / "20auto-upgrades"
    path.write_text('APT::Periodic::Unattended-Upgrade "1";\n')
    assert checks.check_unattended(str(path))[0].status == PASS


def test_unattended_disabled(tmp_path):
    path = tmp_path / "20auto-upgrades"
    path.write_text('APT::Periodic::Unattended-Upgrade "0";\n')
    assert checks.check_unattended(str(path))[0].status == WARN


def test_parse_sshd_first_value_wins_and_ignores_comments():
    text = "# PermitRootLogin yes\nPermitRootLogin no\nPermitRootLogin yes\n"
    assert checks.parse_sshd_config(text)["permitrootlogin"] == "no"


def test_parse_sshd_stops_at_match_block():
    text = "Match User bob\nPasswordAuthentication yes\n"
    assert "passwordauthentication" not in checks.parse_sshd_config(text)


def test_evaluate_ssh_risky():
    settings = {
        "permitrootlogin": "yes",
        "permitemptypasswords": "yes",
        "passwordauthentication": "yes",
    }
    statuses = [r.status for r in checks.evaluate_ssh(settings)]
    assert statuses == [FAIL, FAIL, WARN]


def test_evaluate_ssh_safe():
    settings = {"permitrootlogin": "no", "passwordauthentication": "no"}
    assert all(r.status == PASS for r in checks.evaluate_ssh(settings))


def test_check_ssh_not_installed(tmp_path):
    result = checks.check_ssh(str(tmp_path / "none"), str(tmp_path / "*.conf"))[0]
    assert result.status == SKIP


def test_check_ssh_dropin_overrides_main(tmp_path):
    main = tmp_path / "sshd_config"
    main.write_text("PermitRootLogin yes\n")
    (tmp_path / "10-hardening.conf").write_text("PermitRootLogin no\n")
    results = checks.check_ssh(str(main), str(tmp_path / "*.conf"))
    assert results[0].status == PASS


def test_parse_ss():
    output = (
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
        'tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n'
        'tcp LISTEN 0 128 [::]:80 [::]:* users:(("nginx",pid=2,fd=6))\n'
    )
    items = checks.parse_ss(output)
    assert [(i.port, i.process) for i in items] == [
        ("22", "sshd"),
        ("53", "unknown"),
        ("80", "nginx"),
    ]
    assert [checks.is_exposed(i.address) for i in items] == [True, False, True]


def test_score():
    results = [
        Result("a", PASS, ""),
        Result("b", WARN, ""),
        Result("c", FAIL, ""),
        Result("d", SKIP, ""),
    ]
    assert report.score(results) == 50


def test_render_shows_fix_for_failures():
    text = report.render([Result("x", FAIL, "bad", "do this")], color=False)
    assert "Fix: do this" in text
    assert "Security score: 0/100" in text
