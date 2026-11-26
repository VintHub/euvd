#!/usr/bin/env python3
"""
Download the EUVD <-> CVE mapping CSV from ENISA and split it into one JSON
file per EUVD ID, grouped in directories by year.

Example:
    EUVD-1999-0001 -> ./1999/EUVD-1999-0001.json
                      {"EUVD-1999-0001": "CVE-1999-0001"}

A SHA-256 checksum of the CSV is stored in euvd_last_hash.txt. If the CSV has
the same checksum as last time, the script exits without touching any file.

Only the Python standard library is required.

Usage:
    python euvd_mapping.py                      # download and write to ./
    python euvd_mapping.py -o out_dir           # write to ./out_dir
    python euvd_mapping.py -i local_file.csv    # use a local CSV, no download
    python euvd_mapping.py --force              # ignore the stored checksum
    python euvd_mapping.py --hash-file my.txt   # custom checksum file location
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

URL = "https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping"
HASH_FILENAME = "euvd_last_hash.txt"

EUVD_RE = re.compile(r"EUVD-(\d{4})-\d+", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def download_csv(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (euvd-mapping-script)"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_last_hash(hash_file: Path) -> str | None:
    try:
        return hash_file.read_text(encoding="utf-8").strip() or None
    except FileNotFoundError:
        return None


def write_hash(hash_file: Path, digest: str) -> None:
    hash_file.parent.mkdir(parents=True, exist_ok=True)
    hash_file.write_text(digest + "\n", encoding="utf-8")


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
    parser.add_argument("--hash-file", help=f"checksum file (default: <output>/{HASH_FILENAME})")
    parser.add_argument("--force", action="store_true", help="process even if the checksum is unchanged")
    args = parser.parse_args()

    out_dir = Path(args.output)
    hash_file = Path(args.hash_file) if args.hash_file else out_dir / HASH_FILENAME

    if args.input:
        raw = Path(args.input).read_bytes()
    else:
        print(f"Downloading {URL} ...")
        raw = download_csv(URL)

    digest = sha256_hex(raw)
    if not args.force and digest == read_last_hash(hash_file):
        print(f"CSV unchanged (sha256 {digest}); nothing to do.")
        return 0

    # utf-8-sig strips a BOM if present
    mapping = parse_mapping(raw.decode("utf-8-sig", errors="replace"))
    if not mapping:
        print("No EUVD/CVE pairs found in the CSV.", file=sys.stderr)
        return 1

    n = write_files(mapping, out_dir)

    # Store the checksum only after everything was written, so a failed run
    # is retried next time instead of being mistaken for an up-to-date one.
    write_hash(hash_file, digest)
    print(f"Done: wrote {n} JSON files. Checksum saved to {hash_file}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
