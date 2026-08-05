# 🌐 threat-intel-hub live demo

Browser demo: investigate an IP, domain, email or CVE using free APIs → weighted risk score.

## Try it

- **Render (one-click, recommended):** [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Phanidhar007/threat-intel-hub)
- **Hugging Face Spaces:** Docker Space → `demo/Dockerfile`.
- **Vercel:** import the repo → `api/index.py` + `vercel.json`.

Live demo URL (after deploying): `https://threat-intel-hub-demo.onrender.com`

## Run locally

```bash
pip install -r requirements.txt -r demo/requirements.txt
python demo/app.py          # http://localhost:7860
```

## Free sources used

- Without keys: ip-api.com, Tor exit list, crt.sh, HackerTarget, Have I Been Pwned, OSV
- With free keys (env vars): AbuseIPDB, VirusTotal, GreyNoise Community

## Notes

- Add `ABUSEIPDB_KEY` / `VIRUSTOTAL_KEY` / `GREYNOISE_KEY` as env vars in
  your hosting dashboard for the richest risk scores.
