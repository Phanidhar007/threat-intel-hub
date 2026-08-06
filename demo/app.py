"""threat-intel-hub live web demo (Flask). Queries free APIs + risk score."""

from __future__ import annotations

import html
import os
import sysfrom flask import Flask, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threathub.aggregator import investigate  # noqa: E402
from threathub.cli import _detect_kind  # noqa: E402
from threathub.envs import get as getenv  # noqa: E402

app = Flask(__name__)

BASE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>threat-intel-hub demo</title>
<style>body{{font-family:system-ui;max-width:760px;margin:2rem auto;padding:0 1rem}}
input{{width:100%;padding:.6rem;font-size:1rem}}button{{padding:.6rem 1.2rem;font-size:1rem}}
table{{border-collapse:collapse;width:100%;margin-top:.5rem}}td,th{{border:1px solid #ddd;
padding:.5rem;text-align:left}}pre{{background:#f4f4f4;padding:1rem;overflow:auto}}
.badge{{padding:.2rem .7rem;border-radius:4px;color:#fff}}</style></head>
<body><h1>🧠 threat-intel-hub — live demo</h1>
<p>IP / domain / email / CVE lookup from free sources with a risk score.</p>
<form method="post"><label>Target
<input name="target" placeholder="IP, domain, email or CVE (e.g. 8.8.8.8)" required></label>
<p style="margin-top:.5rem"><button type="submit">Investigate</button></p></form>
{body}</body></html>"""

LEVEL_COLORS = {"benign": "#0a7a0a", "low": "#3e7b00", "medium": "#e65100",
                "high": "#b00020"}


@app.get("/")
def index():
    return BASE.format(body="")


@app.post("/")
def run():
    target = (request.form.get("target") or "").strip()
    if not target:
        return BASE.format(body="<p>Enter a target.</p>")
    try:
        kind = _detect_kind(target)
        report = investigate(target, kind, {"abuseipdb": getenv("ABUSEIPDB_KEY"),
                                            "virustotal": getenv("VIRUSTOTAL_KEY"),
                                            "greynoise": getenv("GREYNOISE_KEY")})
    except Exception as e:
        return BASE.format(body=f"<p>Error: {html.escape(str(e))}</p>")

    risk = report["risk"]
    color = LEVEL_COLORS.get(risk["level"], "#999")
    parts = [f"<h2>{html.escape(target)} <span class='badge' style='background:{color}'>"
             f"{risk['level'].upper()} {risk['score']}/100</span></h2>"]
    if risk["notes"]:
        parts.append("<ul>" + "".join(f"<li>{html.escape(n)}</li>" for n in risk["notes"]) + "</ul>")

    if kind == "email" and report.get("services"):
        parts.append(f"<p>Likely service: <b>{html.escape(', '.join(report['services']))}</b></p>")

    rows = []
    for name, res in report["results"].items():
        if "error" in res:
            rows.append(f"<tr><td>{html.escape(name)}</td><td colspan='2'><i>error: "
                        f"{html.escape(str(res['error'])[:80])}</i></td></tr>")
        else:
            details = " | ".join(f"{k}: {v}" for k, v in res.items()
                                 if k not in ("source",) and v not in ("", None))
            rows.append(f"<tr><td><b>{html.escape(name)}</b></td>"
                        f"<td colspan='2'><code>{html.escape(str(details)[:220])}</code></td></tr>")
    parts.append("<table><tr><th>Source</th><th colspan='2'>Data</th></tr>" +
                 "".join(rows) + "</table>")
    parts.append("<p><small>Add free API keys (AbuseIPDB / VirusTotal / GreyNoise) as env vars "
                 "for richer results.</small></p>")
    dbg = {k: len(os.environ.get(k) or "") for k in
           ("ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "GREYNOISE_KEY")}
    parts.append(f"<p class='debug'>lens={dbg} allkeys={sorted(k for k in os.environ)[:6]}</p>")
    return BASE.format(body="".join(parts))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "7860")))
