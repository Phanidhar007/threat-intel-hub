# threat-intel-hub

> **OSINT & threat intelligence aggregation** with free sources and a weighted risk score — the lightweight, API-driven cousin of [MISP](https://github.com/MISP/MISP) / [OpenCTI](https://github.com/OpenCTI-Platform/opencti) for individual lookups.

Aggregate **IP, domain, email and CVE** intelligence from free services into one JSON report with a 0–100 risk score.

## 🌐 Live demo

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/<Phanidhar007>/threat-intel-hub)

Try the web demo: **`https://threat-intel-hub-demo.onrender.com`** (deploy it first — see [`demo/README.md`](demo/README.md)).

## Sources (all free)

| Category | Source | Key required |
|---|---|---|
| IP geolocation / network | ip-api.com | no |
| IP reputation | AbuseIPDB | free key |
| Malware verdicts | VirusTotal | free key |
| Internet scanning classification | GreyNoise Community | free key |
| Anonymity | Tor exit node list | no |
| Domain / subdomains | crt.sh, HackerTarget | no |
| Email breaches | Have I Been Pwned (k-anonymity API) | no |
| CVEs | OSV.dev | no |

## Install

```bash
git clone https://github.com/<Phanidhar007>/threat-intel-hub.git
cd threat-intel-hub
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
```

Optional free keys (`.env`):

```ini
ABUSEIPDB_KEY=your_free_key
VIRUSTOTAL_KEY=your_free_key
GREYNOISE_KEY=your_free_key
```

## Usage

```bash
# Auto-detect the target kind
python -m threathub 8.8.8.8
python -m threathub example.com
python -m threathub someone@example.com
python -m threathub CVE-2021-44228

# Force a kind
python -m threathub 8.8.8.8 --kind ip --out abuse_case
```

### Sample report (excerpt)

```json
{
  "target": "1.2.3.4",
  "kind": "ip",
  "risk": { "score": 65, "level": "high",
            "notes": ["AbuseIPDB confidence 95%", "VirusTotal: 3 malicious verdicts"] },
  "results": {
    "abuseipdb": { "abuseConfidenceScore": 95, "totalReports": 12, "countryCode": "RU" },
    "virustotal": { "malicious": 3, "suspicious": 1, "reputation": -4 },
    "greynoise": { "classification": "malicious", "noise": true }
  }
}
```

## Risk model

- AbuseIPDB confidence ≥ 50 → +30, ≥ 10 → +10
- VirusTotal ≥ 2 malicious → +30, == 1 → +10
- GreyNoise `malicious` → +20
- Tor exit → +15
- ≥ 50 → **high**, ≥ 20 → **medium**, > 0 → **low**, else **benign**

## Tests

```bash
python -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
