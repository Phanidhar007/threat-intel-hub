"""CLI entry point for threat-intel-hub."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .aggregator import investigate
from .envs import get, load_dotenv


def _detect_kind(target: str) -> str:
    if target.lower().startswith("cve-"):
        return "cve"
    if "@" in target:
        return "email"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threat-intel-hub",
        description="OSINT & threat intel aggregation from free APIs with a risk score.",
        epilog="Free API keys (optional) via .env: ABUSEIPDB_KEY, VIRUSTOTAL_KEY, GREYNOISE_KEY",
    )
    p.add_argument("target", help="IP, domain, email or CVE id")
    p.add_argument("--kind", choices=["ip", "domain", "email", "cve"],
                   default=None, help="override auto-detection")
    p.add_argument("--out", default="intel_report")
    p.add_argument("-V", "--version", action="version", version=f"threat-intel-hub {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    load_dotenv()

    kind = args.kind or _detect_kind(args.target)
    keys = {"abuseipdb": get("ABUSEIPDB_KEY"), "virustotal": get("VIRUSTOTAL_KEY"),
            "greynoise": get("GREYNOISE_KEY")}

    print(f"[*] investigating {args.target} ({kind}) ...")
    report = investigate(args.target, kind, keys)
    report["scanned_at"] = datetime.now(timezone.utc).isoformat()
    report["tool"] = "threat-intel-hub"
    report["version"] = __version__

    out = Path(f"{args.out}.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    risk = report["risk"]
    print(f"[risk] level={risk['level'].upper()} score={risk['score']}/100")
    for note in risk["notes"]:
        print(f"    - {note}")
    for name, res in report["results"].items():
        if "error" in res:
            print(f"[{name}] error: {res['error']}")
        else:
            print(f"[{name}] ok")
    print(f"[+] report written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
