"""API clients for the free sources."""

from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request

UA = "threat-intel-hub/1.0 (OSINT research)"

SERVICE_DOMAINS = {
    "facebook": ["facebook.com", "fb.com"],
    "google": ["google.com", "googleusercontent.com", "gmail.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "amazon": ["amazon.com"],
    "github": ["github.com"],
    "cloudflare": ["cloudflare.com"],
    "twitter/x": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "paypal": ["paypal.com"],
    "apple": ["apple.com"],
    "discord": ["discord.com", "discord.gg"],
    "telegram": ["telegram.org", "t.me"],
    "whatsapp": ["whatsapp.com"],
    "shopify": ["shopify.com", "myshopify.com"],
}


def _get(url: str, headers: dict | None = None, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={**{"User-Agent": UA}, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _json(url: str, headers: dict | None = None, timeout: int = 30):
    return json.loads(_get(url, headers, timeout).decode("utf-8", errors="replace"))


def crtsh(domain: str) -> dict:
    try:
        data = _json(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json")
        subs = set()
        for row in data:
            for n in (row.get("name_value") or "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith("." + domain) or n == domain:
                    subs.add(n)
        return {"source": "crtsh", "count": len(subs), "subdomains": sorted(subs)}
    except Exception as e:
        return {"source": "crtsh", "error": str(e)}


def hackertarget(domain: str) -> dict:
    try:
        raw = _get(f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}")
        subs = []
        for line in raw.decode().splitlines():
            host, _, ip = line.partition(",")
            if host.strip():
                subs.append({"host": host.strip(), "ip": ip.strip()})
        return {"source": "hackertarget", "count": len(subs), "records": subs}
    except Exception as e:
        return {"source": "hackertarget", "error": str(e)}


def ipapi(ip: str) -> dict:
    """ip-api.com free tier (no key, no HTTPS on free tier)."""
    try:
        data = _json(f"http://ip-api.com/json/{ip}?fields=66842623")
        return {"source": "ip-api", **data}
    except Exception as e:
        return {"source": "ip-api", "error": str(e)}


def abuseipdb(ip: str, api_key: str) -> dict:
    try:
        data = _json(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            {"Key": api_key, "Accept": "application/json"})
        return {"source": "abuseipdb", **data.get("data", {})}
    except Exception as e:
        return {"source": "abuseipdb", "error": str(e)}


def virustotal(ip: str, api_key: str) -> dict:
    try:
        data = _json(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                     {"x-apikey": api_key})
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {"source": "virustotal", "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "reputation": attrs.get("reputation"),
                "country": attrs.get("country")}
    except Exception as e:
        return {"source": "virustotal", "error": str(e)}


def greynoise(ip: str, api_key: str) -> dict:
    try:
        data = _json(f"https://api.greynoise.io/v3/community/{ip}",
                     {"key": api_key})
        return {"source": "greynoise", "classification": data.get("classification"),
                "noise": data.get("noise"), "riot": data.get("riot")}
    except Exception as e:
        return {"source": "greynoise", "error": str(e)}


def hibp(email: str) -> dict:
    """Have I Been Pwned — hash-range k-anonymity endpoint (free, no key)."""
    try:
        sha1 = hashlib.sha1(email.encode().lower()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        raw = _get(f"https://api.pwnedpasswords.com/range/{prefix}")
        lines = raw.decode().splitlines()
        found = [ln.split(":")[0] for ln in lines if ln.split(":")[0] == suffix]
        return {"source": "hibp", "pwned": len(found) == 1,
                "count": int(found[0].split(":")[1]) if found else 0}
    except Exception as e:
        return {"source": "hibp", "error": str(e)}


def guess_service(email: str) -> list[str]:
    domain = email.rsplit("@", 1)[-1].lower()
    return [name for name, domains in SERVICE_DOMAINS.items() if domain in domains]


def osv_cve(cve_id: str) -> dict:
    try:
        data = _json(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(cve_id)}")
        return {"source": "osv", "id": data.get("id"), "summary": data.get("summary"),
                "severity": data.get("severity"), "aliases": data.get("aliases", [])}
    except Exception as e:
        return {"source": "osv", "error": str(e)}
