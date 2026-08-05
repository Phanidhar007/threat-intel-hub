"""Aggregate sources into one report with a weighted risk score."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from . import sources


def _score(results: dict) -> dict:
    score = 0
    notes = []

    abuse = results.get("abuseipdb", {})
    if abuse.get("abuseConfidenceScore", 0) >= 50:
        score += 30
        notes.append(f"AbuseIPDB confidence {abuse.get('abuseConfidenceScore')}%")
    elif abuse.get("abuseConfidenceScore", 0) >= 10:
        score += 10

    vt = results.get("virustotal", {})
    if vt.get("malicious", 0) >= 2:
        score += 30
        notes.append(f"VirusTotal: {vt['malicious']} malicious verdicts")
    elif vt.get("malicious", 0) == 1:
        score += 10

    gn = results.get("greynoise", {})
    if gn.get("classification") == "malicious":
        score += 20
        notes.append("GreyNoise classifies as malicious")

    if results.get("tor-exit-list", {}).get("is_tor"):
        score += 15
        notes.append("Traffic observed as Tor exit node")

    if score >= 50:
        level = "high"
    elif score >= 20:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "benign"
    return {"score": min(score, 100), "level": level, "notes": notes}


def tor_exit_check(ip: str) -> dict:
    try:
        raw = sources._get("https://check.torproject.org/torbulkexitlist", timeout=20)
        data = raw.decode("utf-8", errors="replace").splitlines()
    except Exception:
        data = []
    return {"source": "tor-exit-list", "is_tor": ip in data}


def investigate(target: str, kind: str, api_keys: dict, workers: int = 8) -> dict:
    report = {"target": target, "kind": kind, "results": {}}

    def _run(name: str, fn):
        try:
            return fn()
        except Exception as e:
            return {"source": name, "error": str(e)}

    jobs: dict[str, callable] = {}

    if kind == "ip":
        jobs["ip-api"] = lambda: sources.ipapi(target)
        jobs["tor-exit-list"] = lambda: tor_exit_check(target)
        if api_keys.get("abuseipdb"):
            jobs["abuseipdb"] = lambda: sources.abuseipdb(target, api_keys["abuseipdb"])
        if api_keys.get("virustotal"):
            jobs["virustotal"] = lambda: sources.virustotal(target, api_keys["virustotal"])
        if api_keys.get("greynoise"):
            jobs["greynoise"] = lambda: sources.greynoise(target, api_keys["greynoise"])
    elif kind == "domain":
        jobs["crtsh"] = lambda: sources.crtsh(target)
        jobs["hackertarget"] = lambda: sources.hackertarget(target)
    elif kind == "email":
        jobs["hibp"] = lambda: sources.hibp(target)
    elif kind == "cve":
        jobs["osv"] = lambda: sources.osv_cve(target)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_run, n, fn): n for n, fn in jobs.items()}
        for fut in as_completed(futs):
            name = futs[fut]
            report["results"][name] = fut.result()

    if kind == "email":
        report["services"] = sources.guess_service(target)

    scoring = _score(report["results"])
    report["risk"] = scoring
    return report
