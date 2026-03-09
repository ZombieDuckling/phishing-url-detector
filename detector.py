#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd"}


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def score_url(url: str):
    flags = []
    score = 0

    parsed = urlparse(url if re.match(r"^https?://", url) else f"http://{url}")
    host = (parsed.hostname or "").lower()

    if not host:
        flags.append("missing_host")
        score += 20
        return score, flags

    if is_ip(host):
        flags.append("ip_as_domain")
        score += 25

    if "@" in url:
        flags.append("contains_at_symbol")
        score += 15

    if len(url) > 75:
        flags.append("very_long_url")
        score += 10

    if host.count("-") >= 2:
        flags.append("multiple_hyphens")
        score += 8

    labels = host.split(".")
    if len(labels) > 3:
        flags.append("many_subdomains")
        score += 10

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"suspicious_tld:{tld}")
        score += 15

    if host in SHORTENERS:
        flags.append("url_shortener")
        score += 10

    if any(k in url.lower() for k in ["login", "verify", "secure", "update", "password", "wallet"]):
        flags.append("credential_lure_keywords")
        score += 10

    return min(score, 100), flags


def verdict(score: int) -> str:
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def load_urls(single, file_path):
    urls = []
    if single:
        urls.append(single.strip())
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            urls.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])
    return urls


def main():
    p = argparse.ArgumentParser(description="Basic phishing URL detector")
    p.add_argument("--url", help="Single URL to score")
    p.add_argument("--file", help="Path to file with one URL per line")
    p.add_argument("--json-out", help="Write output JSON to file")
    p.add_argument("--csv-out", help="Write output CSV to file")
    args = p.parse_args()

    urls = load_urls(args.url, args.file)
    if not urls:
        raise SystemExit("Provide --url or --file")

    results = []
    for u in urls:
        s, f = score_url(u)
        row = {
            "url": u,
            "risk_score": s,
            "verdict": verdict(s),
            "flags": f,
        }
        results.append(row)
        print(f"[{row['verdict'].upper():6}] score={s:3} url={u}")
        if f:
            print(f"  flags: {', '.join(f)}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as jf:
            json.dump(results, jf, indent=2)

    if args.csv_out:
        with open(args.csv_out, "w", newline="", encoding="utf-8") as cf:
            w = csv.writer(cf)
            w.writerow(["url", "risk_score", "verdict", "flags"])
            for r in results:
                w.writerow([r["url"], r["risk_score"], r["verdict"], ";".join(r["flags"])])


if __name__ == "__main__":
    main()
