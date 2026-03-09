# Phishing URL detector

This project is a beginner-friendly red team portfolio project. It scores URLs
with simple phishing heuristics and explains which indicators triggered.

## What this project does

This script accepts one URL or a file of URLs and returns a risk score,
a verdict, and matching indicators.

- Flags suspicious URL patterns.
- Produces terminal output for quick triage.
- Exports results to JSON or CSV.

## Run it

Run the script with Python 3.10+.

```bash
python3 detector.py --url "http://secure-login-update-account.top/verify"
```

For batch mode:

```bash
python3 detector.py --file urls.txt --json-out results.json --csv-out results.csv
```

## Example indicators

The detector currently checks for:

- Domain is a raw IP address.
- Presence of `@` symbol.
- Excessively long URLs.
- Many subdomains.
- Suspicious top-level domains.
- URL shorteners.
- Credential lure keywords.

## Ethics

Use this project for defensive testing, awareness training, and research only.
