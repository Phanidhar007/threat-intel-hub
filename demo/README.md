# 🌐 threat-intel-hub live demo

Browser demo: investigate an IP, domain, email or CVE using free APIs → weighted risk score.

## Deploy on Vercel (free)

1. Push this repo to GitHub, then import it at [vercel.com](https://vercel.com) � it auto-detects `vercel.json` + `api/index.py`.
2. Your app is live at `https://threat-intel-hub.vercel.app` (or the URL Vercel assigns).

## Run locally

```bash
pip install -r requirements.txt
python demo/app.py          # http://localhost:7860
```

## Free sources used

- Without keys: ip-api.com, Tor exit list, crt.sh, HackerTarget, Have I Been Pwned, OSV
- With free keys (env vars): AbuseIPDB, VirusTotal, GreyNoise Community

## Notes

- Add `ABUSEIPDB_KEY` / `VIRUSTOTAL_KEY` / `GREYNOISE_KEY` as env vars in
  your hosting dashboard for the richest risk scores.
