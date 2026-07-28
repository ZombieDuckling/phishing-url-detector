# Phishing URL detector

A beginner-friendly **red team portfolio project** that scores suspicious URLs
using lightweight phishing heuristics. It is designed to demonstrate practical
tradecraft awareness, detection logic, and explainable output.

## Portfolio summary

This project shows that you can:

- break phishing detection into explainable signals,
- convert signals into a simple risk model,
- produce analyst-friendly outputs for triage.

### MITRE ATT&CK mapping (high level)

- **T1566: Phishing**
- **T1583/T1584 (contextual): Infrastructure used in phishing campaigns**

## Features

The detector accepts a single URL or a file of URLs and returns:

- risk score (`0-100`),
- risk verdict (`low`, `medium`, `high`),
- triggered indicators.

It supports export to JSON and CSV.

## Project structure

```text
.
├── detector.py
├── tests/
│   └── test_detector.py
├── .github/
│   └── workflows/ci.yml
└── README.md
```

## Quick start

Use Python 3.10+.

```bash
python3 detector.py --url "http://secure-login-update-account.top/verify"
```

Batch mode:

```bash
python3 detector.py --file urls.txt --json-out results.json --csv-out results.csv
```

Run the test suite:

```bash
python3 -m pip install pytest
python3 -m pytest -q
```

## Sample output

```text
[MEDIUM] score= 33 url=http://secure-login-update-account.top/verify
  flags: multiple_hyphens, suspicious_tld:top, credential_lure_keywords
```

## Detection logic

The current version checks for:

- domain is a raw IP address,
- `@` symbol in URL,
- very long URL,
- many subdomains,
- suspicious TLDs,
- URL shorteners,
- credential-lure keywords.

## What I learned

- Simple heuristic models are fast to build and easy to explain.
- Explainable flags are useful for analyst confidence.
- Detection quality improves by iterating on false positives.

## Roadmap

- Add optional WHOIS/domain age enrichment.
- Add URL decoding and obfuscation checks.
- Add a tiny web UI for demo screenshots.
- Expand test cases with real-world benign and malicious URL fixtures.

## Ethics

Use this project for defensive testing, awareness training, and research only.
