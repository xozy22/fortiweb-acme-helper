from acme_helper import certbot_runner


def test_certonly_args(cfg, monkeypatch):
    monkeypatch.setattr(certbot_runner, "certbot_executable", lambda: "/usr/bin/certbot")
    args = certbot_runner.certonly_args(cfg, cfg.certificates[0], force=True, dry_run=False)
    assert args[0] == "/usr/bin/certbot"
    assert "--staging" in args
    assert args[args.index("--cert-name") + 1] == "wc-example"
    assert args.count("-d") == 2 and "*.example.com" in args
    assert "--force-renewal" in args and "--dry-run" not in args
    auth_hook = args[args.index("--manual-auth-hook") + 1]
    assert "auth" in auth_hook and '"' not in auth_hook  # certbot sucht das erste Wort im PATH
    assert str(cfg.letsencrypt_dir) in args


def test_hook_command_prefers_console_script(monkeypatch):
    monkeypatch.setattr(certbot_runner.shutil, "which", lambda name: "/usr/local/bin/" + name)
    assert certbot_runner.hook_command("auth") == "/usr/local/bin/acme-helper-auth-hook"
    monkeypatch.setattr(certbot_runner.shutil, "which", lambda name: None)
    cmd = certbot_runner.hook_command("cleanup")
    assert cmd.endswith("-m acme_helper.hooks.cleanup") and '"' not in cmd


def test_directory_url_overrides_staging(cfg, monkeypatch):
    monkeypatch.setattr(certbot_runner, "certbot_executable", lambda: "certbot")
    cfg.acme.directory_url = "https://ca.example/dir"
    args = certbot_runner.base_args(cfg)
    assert "--staging" not in args and args[args.index("--server") + 1] == "https://ca.example/dir"
