# Changelog

Format changes to the published feed. `feed.json` carries the current `schema_version`. Paths and columns that
exist stay stable within a major version; additions bump the minor version.

## 1.1

Added:

- `latest/anonymizers-7d.txt`: VPN and Tor exits (records tagged `vpn-exit` or `tor-exit`), IPv4 and IPv6 `/64`.
  These records stay in `attackers-*.csv` and `records-7d.ndjson.gz` with their tag, and are no longer in any
  `ipv4-*`/`ipv6-*` list, `top*`, `cidr32`, nftables, ipset, MikroTik, CrowdSec, Defender, Suricata IP
  reputation/dataset or Zeek `Intel::ADDR`/`Intel::SUBNET` entry. In MISP they are `ip-src` attributes with
  `to_ids: false` (the tags are in the comment); in STIX their indicators have `indicator_types: ["anonymization"]`
  instead of `malicious-activity`. Earlier MISP events drop an address once it is tagged as an anonymizer.
- `latest/ipv4-added-1d.txt` and `latest/ipv4-removed-1d.txt`: addresses that entered `ipv4-7d.txt` since the
  previous build, and addresses that aged out of it into the 30-day tail. An address removed on request or newly
  allowlisted is not listed as removed. Both are empty on the first build.
- `history.json`: daily totals for the last 90 days (`day`, `generated`, `ips_7d`, `active_24h`, `added`,
  `removed`, `cves`, `urls`, `hashes`, `scanners`, `anonymizers`). No addresses.
- `og.png` (1200×630) and `og-github.png` (1280×640) social preview images.
- `feed.json`: `schema_version`; `stats.published.anonymizers`.

Changed:

- `defender/defender-top500.csv` leaves out VPN/Tor exits and records whose only tag is `web-scan`;
  `GenerateAlert` is `False` for Severity Low.
- `user-agents-7d.txt` keeps only distinctive attack-tool user agents: browser strings, HTTP libraries and
  self-identified bots, crawlers and scanners are dropped.
- `paths-7d.txt` drops common legitimate endpoints and paths that encode a target (`@`, long hex or base64 runs,
  `/s/<token>/`). `suricata/datasets/paths.lst` only holds CVE-linked paths or paths with an exploit pattern.
- `cves-7d.csv` lists every CVE that appears in a published IP record; `name` may be empty and `kev` empty when
  unknown. `stats.published.cves` counts its rows.
- `fingerprints.csv` and `hassh.csv` drop types they cannot represent (such as JA3); `stats.published.fingerprints`
  counts the rows they hold.
- `SHA256SUMS` covers `feed.json` (it already did; now documented and tested).

## 1.0

Initial release: IPv4/IPv6 block lists, top lists, URLs, domains, hashes, CVEs, JA4+/HASSH fingerprints, user agents,
paths, passwords, CSV/NDJSON records, STIX 2.1, MISP feed, Zeek, Suricata, MikroTik, nftables, ipset, CrowdSec and
Defender formats, `feed.json`, `stats.json`, `SHA256SUMS` signed with minisign.
