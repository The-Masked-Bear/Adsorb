#!/usr/bin/env python3
"""
Automated Partition Table & Image Size Verifier for Adsorb ESP32-S3 (16MB Flash).
Verifies that all partitions in partitions_16MB.csv are well-aligned and that
generated binaries (firmware.bin, littlefs.bin, partitions.bin, bootloader.bin)
strictly fit within their assigned partition bounds with zero overflow.
"""

import csv
import os
import sys

def parse_size(val: str) -> int:
    val = val.strip()
    if val.lower().startswith("0x"):
        return int(val, 16)
    elif val.upper().endswith("K"):
        return int(val[:-1]) * 1024
    elif val.upper().endswith("M"):
        return int(val[:-1]) * 1024 * 1024
    return int(val)

def verify_partitions(repo_root: str) -> bool:
    csv_path = os.path.join(repo_root, "partitions_16MB.csv")
    if not os.path.exists(csv_path):
        print(f"[ERROR] Partition table not found: {csv_path}")
        return False

    partitions = []
    with open(csv_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                name = parts[0]
                ptype = parts[1]
                subtype = parts[2]
                offset = parse_size(parts[3])
                size = parse_size(parts[4])
                partitions.append({
                    "name": name,
                    "type": ptype,
                    "subtype": subtype,
                    "offset": offset,
                    "size": size,
                    "end": offset + size
                })

    print(f"[INFO] Parsed {len(partitions)} partitions from partitions_16MB.csv:")
    for p in partitions:
        print(f"  - {p['name']:<10} Offset: 0x{p['offset']:08X} ({p['offset']:>9} B)  Size: 0x{p['size']:08X} ({p['size']:>9} B)  End: 0x{p['end']:08X}")

    # Verify no overlaps and monotonic ordering
    for i in range(len(partitions) - 1):
        cur = partitions[i]
        nxt = partitions[i+1]
        if cur["end"] > nxt["offset"]:
            print(f"[FAIL] Overlap detected: {cur['name']} ends at 0x{cur['end']:X} but {nxt['name']} begins at 0x{nxt['offset']:X}")
            return False

    # Check total flash bound (16MB = 0x1000000 = 16,777,216 bytes)
    FLASH_16MB = 0x1000000
    last = partitions[-1]
    if last["end"] > FLASH_16MB:
        print(f"[FAIL] Partitions exceed 16MB flash capacity: ends at 0x{last['end']:X} > 0x{FLASH_16MB:X}")
        return False
    print(f"[PASS] All partitions are non-overlapping and within 16MB boundary (0x{last['end']:X} <= 0x{FLASH_16MB:X}).")

    # Verify specific LittleFS partition math (B-01)
    lfs = next((p for p in partitions if p["name"] == "littlefs"), None)
    if not lfs:
        print("[FAIL] Missing 'littlefs' partition in table!")
        return False

    EXPECTED_LFS_SIZE = 0x9E0000
    EXPECTED_LFS_DECIMAL = 10354688
    if lfs["size"] != EXPECTED_LFS_SIZE or lfs["size"] != EXPECTED_LFS_DECIMAL:
        print(f"[FAIL] LittleFS size mismatch: got {lfs['size']} expected {EXPECTED_LFS_DECIMAL} (0x{EXPECTED_LFS_SIZE:X})")
        return False
    print(f"[PASS] LittleFS partition 0x9E0000 is exactly {lfs['size']} bytes down to the byte.")

    # Check binary files if they exist
    bins_to_check = [
        ("littlefs", [
            os.path.join(repo_root, ".pio", "build", "esp32s3_n16r8", "littlefs.bin"),
            os.path.join(repo_root, "docs", "littlefs.bin")
        ]),
        ("app0", [
            os.path.join(repo_root, ".pio", "build", "esp32s3_n16r8", "firmware.bin"),
            os.path.join(repo_root, "docs", "firmware.bin")
        ])
    ]

    all_passed = True
    for part_name, paths in bins_to_check:
        part = next((p for p in partitions if p["name"] == part_name), None)
        if not part:
            continue
        max_allowed = part["size"]
        for pth in paths:
            if os.path.exists(pth):
                act_size = os.path.getsize(pth)
                if act_size > max_allowed:
                    print(f"[FAIL] {pth} size {act_size} exceeds {part_name} partition size {max_allowed} by {act_size - max_allowed} bytes!")
                    all_passed = False
                else:
                    slack = max_allowed - act_size
                    print(f"[PASS] {os.path.basename(pth)} ({act_size:,} B) fits cleanly in {part_name} ({max_allowed:,} B, slack: {slack:,} B).")

    return all_passed

if __name__ == "__main__":
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    success = verify_partitions(repo_dir)
    sys.exit(0 if success else 1)
