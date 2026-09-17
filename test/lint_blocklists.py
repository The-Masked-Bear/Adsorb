#!/usr/bin/env python3
"""
Blocklist Linter & Statistics Analyzer for Adsorb.
Validates RFC-compliant domain formats in data/ blocklists, detects malformed
or junk domains, and prints exact rule and deduplicated PSRAM hash counts.
"""

import os
import re
import sys

DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-_]{1,63}(?<!-)(\.[A-Za-z0-9-_]{1,63}(?<!-))*\.[A-Za-z0-9-_]{2,}$"
)

def lint_file(filepath: str):
    basename = os.path.basename(filepath)
    if not os.path.exists(filepath):
        print(f"[WARN] File not found: {filepath}")
        return set(), 0, 0

    valid_domains = set()
    total_lines = 0
    malformed_lines = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for idx, line in enumerate(f, 1):
            total_lines += 1
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Strip any protocol or leading/trailing slashes if present
            clean = line.lower()
            if "://" in clean:
                clean = clean.split("://", 1)[1]
            clean = clean.split("/", 1)[0].split(":", 1)[0].strip()

            # Verify domain format
            if DOMAIN_REGEX.match(clean):
                valid_domains.add(clean)
            else:
                malformed_lines += 1
                if malformed_lines <= 5:
                    print(f"  [LINT] {basename}:{idx} invalid domain syntax: '{line}' -> '{clean}'")

    print(f"[{basename}] Total lines: {total_lines:,} | Valid rules: {len(valid_domains):,} | Malformed: {malformed_lines}")
    return valid_domains, total_lines, malformed_lines

def main():
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    data_dir = os.path.join(repo_dir, "data")

    file1 = os.path.join(data_dir, "ads-domains.txt")
    file2 = os.path.join(data_dir, "ad-domains2.0.txt")

    print("[INFO] Starting Blocklist Quality & Format Linter...")
    domains1, tot1, mal1 = lint_file(file1)
    domains2, tot2, mal2 = lint_file(file2)

    combined = domains1 | domains2
    print("------------------------------------------------------------------------")
    print(f"Combined Unique Valid Domains: {len(combined):,}")
    psram_usage = len(combined) * 8
    print(f"PSRAM 64-bit FNV-1a Hash Memory Footprint: {psram_usage:,} bytes ({psram_usage / 1024 / 1024:.2f} MB)")
    print("------------------------------------------------------------------------")

    if mal1 > 0 or mal2 > 0:
        print(f"[WARN] Detected {mal1 + mal2} malformed domain strings.")
    else:
        print("[PASS] 100% of blocklist domains are RFC compliant.")

    return 0

if __name__ == "__main__":
    sys.exit(main())
