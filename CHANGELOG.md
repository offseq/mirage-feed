# Changelog

Format changes to the published feed. `feed.json` carries the current `schema_version`. Paths and columns that
exist stay stable within a major version; additions bump the minor version.

## 1.2

Added:

- `latest/lookup/v4/<first octet>.json` and `latest/lookup/v6/<first hextet>.json`: every address in the IP lists
  (`ipv4-*`, `ipv6-7d`, `anonymizers-7d`, `known-scanners-*`), keyed by the value as listed, with `lists` (the files
  that hold it) and, for 7-day records, `record` (the `records-7d.ndjson.gz` fields without `window`). Each shard is
  in `SHA256SUMS`; `feed.json` has one `latest/lookup/` entry (`format: ip-lookup-shards`) whose `count` is the
  number of addresses, `files` the number of shards and `sha256` the hash of the shards' `SHA256SUMS` lines.
- The minisign trusted comment is `mirage-feed <day> generated <generated>`.

Changed:

- `ipv4-removed-1d.txt` holds every address that left `ipv4-7d.txt` since the previous day's build: aged out,
  removed on request, newly allowlisted or reclassified as a VPN/Tor exit. Yesterday's list plus `added` minus
  `removed` is today's list. A rebuild of the same day keeps the diff against the day before rather than emptying it.
- `stats.published` is counted from the published files: `ips`, `active_24h` and `ips_30d` are the block-listable
  addresses (VPN/Tor exits excluded) in the 7-, 1- and 30-day windows, `asns` and `countries` are distinct over the
  7-day ones, `urls`, `hashes` and `scanners` are the rows of their files. `stats.observed` is unchanged.
- MISP: an IP pruned from an earlier event stays in it with `deleted: true`, `to_ids: false` and a new
  `timestamp`, and the event's `timestamp` and `publish_timestamp` move, so subscribed instances drop it.
- STIX indicators: `created` is the first sighting and stays the same for an id from one build to the next;
  `modified` is the build time. `valid_until` and the Defender `ExpirationTime` are at least one day after the build.
- `ipset/mirage.ipset` creates both sets with `maxelem 1048576`, so a restore into yesterday's sets never fails on
  size.
- Upstream records with missing or malformed counts or timestamps are dropped instead of failing the build.

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
- `cves-7d.csv` lists every CVE that appears in a published IP record (`name` may be empty);
  `stats.published.cves` counts its rows. `kev` is true when the snapshot says so or the CVE is in the CISA KEV
  catalog vendored as `generator/kev.txt` (refreshed by hand with `python -m generator.refresh_kev`).
- `fingerprints.csv` and `hassh.csv` drop types they cannot represent (such as JA3); `stats.published.fingerprints`
  counts the rows they hold.
- `attackers-ipv4-7d.csv` (the OpenCTI CSV feed) leaves out rows without an ASN, which the mapper's
  Autonomous-System entity cannot take; `attackers-7d.csv` keeps them.
- `suricata/mirage.rules` sid 1900001 rev 2 matches any listed address (`iprep:...,>,0`); rev 1 used `>,50`, which
  missed addresses with confidence 39 or lower.
- `stix/mirage.json` orders objects as marking definitions, identity, other objects, then relationships, so every
  reference points to an earlier object.
- `mikrotik/mirage-7d.rsc` omits the `/ipv6 firewall address-list` section when there are no IPv6 entries.
- `SHA256SUMS` covers `feed.json` (it already did; now documented and tested).

## 1.0

Initial release: IPv4/IPv6 block lists, top lists, URLs, domains, hashes, CVEs, JA4+/HASSH fingerprints, user agents,
paths, passwords, CSV/NDJSON records, STIX 2.1, MISP feed, Zeek, Suricata, MikroTik, nftables, ipset, CrowdSec and
Defender formats, `feed.json`, `stats.json`, `SHA256SUMS` signed with minisign.
