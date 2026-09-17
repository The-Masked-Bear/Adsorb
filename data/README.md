# Adsorb Blocklists & Domain Curation

Adsorb loads dual blocklists into Octal PSRAM at startup, organizing them into a sorted array of 64-bit non-cryptographic FNV-1a hashes for ultra-fast binary search domain resolution.

## File Breakdown

| File | Rules | Purpose | Description |
|------|-------|---------|-------------|
| `ads-domains.txt` | 55,032 | Core Ad & Tracker Blacklist | Curated high-confidence advertising, telemetry, spyware, and malware domains. |
| `ad-domains2.0.txt` | 200,000 | Extended Threat Intelligence | Deep-coverage blacklist tracking analytics beacons, cross-site trackers, and ad-serving CDN infrastructure. |
| `custom_whitelist.txt` | Variable | Local System & OTT Whitelist | User and appliance exceptions (e.g. Zee5 OTT, Jio STB, streaming CDNs). Overrides all blocklists. |
| `custom_blacklist.txt` | Variable | Custom Local Blacklist | User-specified domain bans managed via the web dashboard or REST API. |
| `bypass_ips.txt` | Variable | Per-Client IP Bypasses | LAN IP addresses that bypass ad blocking completely (e.g. for developer devices or troubleshooting). |

## Statistics & Footprint

- **Total Raw Rules**: 255,032
- **Unique Deduplicated Domains**: 255,024
- **PSRAM Footprint**: 2,040,192 bytes (~1.95 MB) of 8 MB Octal PSRAM.
- **Lookup Complexity**: \(O(\log N)\) binary search across domain label hierarchy.
- **Flash Wear**: Zero. Blocklists are loaded into RAM at boot; lookups are completely in-memory.

## Sources & Upstream Feeds

- [StevenBlack Unified Hosts](https://github.com/StevenBlack/hosts)
- [AdGuard DNS Filter](https://github.com/AdguardTeam/AdguardFilters)
- [Peter Lowe's Blocklist](https://pgl.yoyo.org/adservers/)
- [Anudeep's Blacklist](https://github.com/anudeepND/blacklist)
