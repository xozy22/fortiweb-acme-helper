"""Prüfskript gegen eine echte FortiWeb: funktionieren Listen, Intermediate-Upload, Gruppe und Member?

Liest Zugangsdaten aus einer .env-Datei (Default: .env.fwtest neben dem Repo), damit sie nie in
Terminal oder Log auftauchen. Legt nur Objekte mit dem Präfix "acmeprobe-" an und löscht sie wieder.

    python scripts/fw_probe.py --host 10.0.53.2 --port 443 [--env .env.fwtest] [--pem datei.pem ...]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from acme_helper.errors import FortiWebError  # noqa: E402
from acme_helper.fortiweb.client import FortiWebClient, get_field  # noqa: E402

PREFIX = "acmeprobe-"


def load_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def step(title: str) -> None:
    print(f"\n== {title}")


def try_call(label: str, fn):
    try:
        res = fn()
        print(f"  [ok]   {label}" + (f" -> {str(res)[:160]}" if res not in (None, "") else ""))
        return True, res
    except FortiWebError as exc:
        print(f"  [FAIL] {label}: {str(exc)[:300]}")
        return False, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--env", default=str(Path(__file__).resolve().parents[1] / ".env.fwtest"))
    ap.add_argument("--pem", nargs="*", default=[], help="Intermediate-PEM-Dateien zum Anlegen-Test")
    ap.add_argument("--keep", action="store_true", help="Testobjekte nicht löschen")
    args = ap.parse_args()

    env = load_env(Path(args.env))
    user, pw = env.get("FW_USER"), env.get("FW_PASS")
    if not user or not pw:
        print(f"FW_USER/FW_PASS fehlen in {args.env}")
        return 2
    client = FortiWebClient(host=args.host, port=args.port, username=user, password=pw, verify=False,
                            vdom=env.get("FW_VDOM", "root"))

    step("Verbindung und Listen")
    ok, certs = try_call("lokale Zertifikate (cmdb)", client.list_local_certificates)
    if not ok:
        return 1
    try_call("Intermediates (cmdb)", client.list_intermediate_certificates)
    try_call("Intermediate-Gruppen", lambda: [get_field(g, "name") for g in client._list("inter_group")])
    try_call("SNI-Gruppen", lambda: [get_field(g, "name") for g in client._list("sni_group")])
    ok, pols = try_call("Server Policies", lambda: [get_field(p, "name") for p in client._list("server_policy")])

    step("Rohantwort GET cmdb (erste Objekte, zur Feldanalyse)")
    for key in ("local_cert", "inter_cert", "inter_group", "sni_group"):
        try:
            items = client._list(key)
            print(f"  {key}: {json.dumps(items[:1])[:600]}")
        except FortiWebError as exc:
            print(f"  {key}: {str(exc)[:200]}")

    created: list[tuple[str, str]] = []  # (key, name)

    step("Intermediate hochladen, Gruppe anlegen, Member per Untertabelle")
    for idx, pem_path in enumerate(args.pem):
        pem = Path(pem_path).read_text(encoding="utf-8").strip() + "\n"
        ok, name = try_call(f"Upload {Path(pem_path).name}", lambda p=pem: client.import_intermediate_certificate("acmeprobe", p))
        if ok:
            created.append(("inter_cert", name))
    if created:
        gname = f"{PREFIX}group"
        ok, _ = try_call("Gruppe POST", lambda: client.create_intermediate_group(gname))
        if ok:
            created.append(("inter_group", gname))
            try_call("Member POST", lambda: client.add_intermediate_group_member(gname, created[0][1]))
            try_call("Member lesen", lambda: [get_field(m, "name") for m in client.list_intermediate_group_members(gname)])
            try_call("Member erneut (no-op)", lambda: client.add_intermediate_group_member(gname, created[0][1]))

    if pols:
        step("Server Policy: GET-Objekt (Felder für PUT)")
        pol = client.get_server_policy(pols[0])
        print("  Felder:", ", ".join(sorted(pol.keys()))[:1500])
        print("  certificate =", repr(get_field(pol, "certificate")), "| ssl =", get_field(pol, "ssl"),
              "| certificate-type =", get_field(pol, "certificate-type"), "| multi-certificate =", get_field(pol, "multi-certificate"))

    if created and not args.keep:
        step("Aufräumen")
        for key, name in reversed(created):
            try_call(f"DELETE {key} {name}", lambda k=key, n=name: client._request("DELETE", k, params={"mkey": n}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
