#!/usr/bin/env python3
"""
Download the EUVD <-> CVE mapping CSV from ENISA and split it into one JSON
file per EUVD ID, grouped in directories by year.

Example:
    EUVD-1999-0001 -> ./1999/EUVD-1999-0001.json
                      {"EUVD-1999-0001": "CVE-1999-0001"}

Only the Python standard library is required.

Usage:
    python euvd_mapping.py                      # download and write to ./
    python euvd_mapping.py -o out_dir           # write to ./out_dir
    python euvd_mapping.py -i local_file.csv    # use a local CSV, no download
"""

import argparse
import json
import re
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

URL = "https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping"

EUVD_RE = re.compile(r"EUVD-(\d{4})-\d+", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def download_csv(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (euvd-mapping-script)"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read()
    # utf-8-sig strips a BOM if present
    return raw.decode("utf-8-sig", errors="replace")


def parse_mapping(csv_text: str) -> dict[str, list[str]]:
    """
    Return {EUVD_ID: [CVE_ID, ...]}.

    Each line is scanned with regexes, so this works regardless of the
    delimiter (comma, semicolon, tab), quoting, column order or header row.
    """
    mapping: dict[str, list[str]] = defaultdict(list)

    for line in csv_text.splitlines():
        euvd = EUVD_RE.search(line)
        cve = CVE_RE.search(line)
        if not euvd or not cve:
            continue  # header row, blank line, or malformed line

        euvd_id = euvd.group(0).upper()
        cve_id = cve.group(0).upper()
        if cve_id not in mapping[euvd_id]:
            mapping[euvd_id].append(cve_id)

    return mapping


def write_files(mapping: dict[str, list[str]], out_dir: Path) -> int:
    count = 0
    for euvd_id, cves in mapping.items():
        year = EUVD_RE.match(euvd_id).group(1)
        year_dir = out_dir / year
        year_dir.mkdir(parents=True, exist_ok=True)

        # One CVE -> plain string, as requested. If an EUVD ID maps to
        # several CVEs, keep them all as a list instead of losing data.
        value = cves[0] if len(cves) == 1 else cves

        with open(year_dir / f"{euvd_id}.json", "w", encoding="utf-8") as f:
            json.dump({euvd_id: value}, f, ensure_ascii=False)
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("-o", "--output", default=".", help="output directory (default: current)")
    parser.add_argument("-i", "--input", help="read this local CSV instead of downloading")
    args = parser.parse_args()

    if args.input:
        csv_text = Path(args.input).read_text(encoding="utf-8-sig")
    else:
        print(f"Downloading {URL} ...")
        csv_text = download_csv(URL)

    mapping = parse_mapping(csv_text)
    if not mapping:
        print("No EUVD/CVE pairs found in the CSV.", file=sys.stderr)
        return 1

    n = write_files(mapping, Path(args.output))
    print(f"Done: wrote {n} JSON files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
