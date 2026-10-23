<h1 align="center">Mirage Feed</h1>

<p align="center">
Daily threat intelligence from the <a href="https://mirage.offseq.com">OffSeq Mirage</a> honeypot fleet.<br>
Handshake-verified attacker IPs, exploited CVEs, payload URLs and fingerprints,<br>
in the formats your firewall, SIEM and threat-intel platform already read.
</p>

<p align="center">
<img alt="Updated daily" src="https://img.shields.io/github/last-commit/offseq/mirage-feed/data?label=updated&style=flat-square&color=0b6e8a">
<img alt="License CC BY 4.0" src="https://img.shields.io/badge/data-CC%20BY%204.0-0b6e8a?style=flat-square">
<img alt="TLP:CLEAR" src="https://img.shields.io/badge/TLP-CLEAR-ffffff?style=flat-square&labelColor=1f2937">
</p>

---

<!-- stats:start -->
### Last 24 hours

| | Mirage observed | In this feed |
|---|---:|---:|
| Source IPs | 8,250 | 3,115 |
| Networks (ASNs) | 747 | 393 |
| Countries | 102 | 74 |
| CVEs exploited (all CISA KEV) | 9 | 10 |
| Payload / download URLs | 3 | 2 |
| Malware hashes | 0 | 2 |
| Tooling fingerprints | — | 200 |
| Research scanners (excluded) | — | 3,736 |
| Credential pairs tried | 128,261 | top 100 passwords |
| Session transcripts | 2.07M events | — |

<sub>Snapshot 2026-10-23 20:18 UTC · entries are published 24 h after first sighting · <a href="#how-an-ip-gets-listed">methodology</a></sub>
<!-- stats:end -->

## Quick start

Point your tool at a stable URL. Files are rebuilt every day; the paths never change.

| Use | URL |
|---|---|
| IPv4 blocklist, last 7 days | `https://feeds.offseq.com/mirage-feed/latest/ipv4-7d.txt` |
| IPv4 top 1,000 (for small firewall tables) | `https://feeds.offseq.com/mirage-feed/latest/ipv4-top1k.txt` |
| Payload and C2 URLs | `https://feeds.offseq.com/mirage-feed/latest/urls-7d.txt` |
| Malware SHA-256 | `https://feeds.offseq.com/mirage-feed/latest/hashes-sha256-30d.txt` |
| Full records (CSV) | `https://feeds.offseq.com/mirage-feed/latest/attackers-7d.csv` |
| STIX 2.1 bundle | `https://feeds.offseq.com/mirage-feed/latest/stix/mirage.json` |
| MISP feed (add as a MISP Feed) | `https://feeds.offseq.com/mirage-feed/misp/` |

Plain lists hold one value per line with no comments, so they load as-is into
pfBlockerNG, OPNsense aliases, FortiGate threat feeds and Palo Alto EDLs.

## Integrations

<details>
<summary><b>pfSense / OPNsense</b></summary>

Firewall → Aliases → Add. Type **URL Table (IPs)**, URL `https://feeds.offseq.com/mirage-feed/latest/ipv4-7d.txt`,
refresh **1 day**. Use the alias as the source in a block rule on WAN.
</details>

<details>
<summary><b>FortiGate</b></summary>

```
config system external-resource
    edit "mirage-feed"
        set type address
        set resource "https://feeds.offseq.com/mirage-feed/latest/ipv4-7d.txt"
        set refresh-rate 1440
    next
end
```
</details>

<details>
<summary><b>Palo Alto (EDL)</b></summary>

Objects → External Dynamic Lists → Add. Type **IP List**, source
`https://feeds.offseq.com/mirage-feed/latest/ipv4-7d.txt`, repeat **Daily**. Firewalls with a 50k EDL
budget should use `ipv4-top1k.txt` or `ipv4-top10k.txt`.
</details>

<details>
<summary><b>MikroTik RouterOS</b></summary>

```
/tool fetch url="https://feeds.offseq.com/mirage-feed/latest/mikrotik/mirage-7d.rsc" dst-path=mirage.rsc
/import file-name=mirage.rsc
```
Entries carry `timeout=7d`, so they expire on their own.
</details>

<details>
<summary><b>nftables / ipset</b></summary>

```sh
curl -fsSL --create-dirs -o /etc/nftables.d/mirage.nft https://feeds.offseq.com/mirage-feed/latest/nft/mirage.nft
nft -f /etc/nftables.d/mirage.nft
```
The file defines table `inet mirage_feed` with drop rules on the `input` hook and, for routers, the
`forward` hook. It flushes its own sets and chains first, so re-running it is safe.

```sh
curl -fsSL https://feeds.offseq.com/mirage-feed/latest/ipset/mirage.ipset | ipset restore
iptables -C INPUT -m set --match-set mirage4 src -j DROP 2>/dev/null \
  || iptables -I INPUT -m set --match-set mirage4 src -j DROP
ip6tables -C INPUT -m set --match-set mirage6 src -j DROP 2>/dev/null \
  || ip6tables -I INPUT -m set --match-set mirage6 src -j DROP
```
</details>

<details>
<summary><b>CrowdSec</b></summary>

```sh
curl -fsSL https://feeds.offseq.com/mirage-feed/latest/ipv4-7d.txt -o mirage.txt
cscli decisions import -i mirage.txt --format values --duration 48h --scope ip --reason mirage-feed
```
</details>

<details>
<summary><b>Suricata and Zeek</b></summary>

Suricata IP reputation: `latest/suricata/categories.txt` and `latest/suricata/mirage-iprep.list`.

```
alert ip any any -> $HOME_NET any (msg:"Mirage feed: known attacker"; iprep:src,MirageAttacker,>,50; threshold:type limit,track by_src,count 1,seconds 3600; sid:1900001; rev:1;)
```

`latest/suricata/mirage.rules` holds that rule plus alert-only, rate-limited hunting rules for attacker
user agents and request paths and a payload SHA-256 rule. Copy the whole `suricata/` directory so the
`datasets/` paths resolve.

Zeek Intel framework:

```zeek
redef Intel::read_files += { "/opt/mirage/mirage.intel" };
```
</details>

<details>
<summary><b>MISP, OpenCTI, Sentinel, Splunk</b></summary>

- **MISP**: Sync Actions → Feeds → Add. Source format **MISP Feed**, URL `https://feeds.offseq.com/mirage-feed/misp/`.
- **OpenCTI**: Data → Ingestion → CSV feeds, URL `https://feeds.offseq.com/mirage-feed/latest/attackers-ipv4-7d.csv`, with the mapper in
  [`docs/opencti-csv-mapper.json`](docs/opencti-csv-mapper.json). Or import `latest/stix/mirage.json` as a file.
- **Microsoft Sentinel**: the Upload Indicators API takes at most 100 objects per request, wrapped as
  `{"sourcesystem": "OffSeq Mirage", "stixobjects": [...]}`. [`scripts/sentinel-upload.sh`](scripts/sentinel-upload.sh)
  splits `latest/stix/mirage.json` that way.
- **Defender for Endpoint**: import `latest/defender/defender-top500.csv` (the 500 highest-confidence IPv4 addresses,
  one CSV import batch).
- **Splunk**: add `latest/attackers-7d.csv` as a lookup and match its `ip` column against `src_ip`.
</details>

## What's in the feed

| File | Contents |
|---|---|
| `ipv4-{1d,7d,30d}.txt` | Attacker IPv4 addresses by activity window |
| `ipv4-top{1k,10k}.txt` | Ranked by confidence, sized for capped firewall tables |
| `ipv4-7d-cidr32.txt` · `ipv6-7d.txt` | IPv4 with `/32` suffix (AWS WAF IP sets) and IPv6 `/64` networks |
| `known-scanners-ipv4.txt` · `known-scanners-ipv6.txt` | Research scanners we saw and **excluded** (Shodan, Censys, Shadowserver …). Allowlist these if you like. |
| `urls-7d.txt` · `domains-7d.txt` | Payload, dropper and C2 locations from captured exploit attempts |
| `hashes-sha256-30d.txt` | Files those payloads delivered |
| `cves-7d.csv` | CVEs exploited against the fleet, with CISA KEV flag and attempt counts |
| `fingerprints.csv` · `hassh.csv` | JA4+ fingerprints of attacker tooling (FoxIO column layout) and SSH HASSH |
| `user-agents-7d.txt` · `paths-7d.txt` | HTTP user agents and request paths seen in attacks. For hunting, not blocking |
| `passwords-top100.txt` | The 100 passwords attackers tried most, without usernames |
| `attackers-7d.csv` · `attackers-ipv4-7d.csv` · `records-7d.ndjson.gz` | One record per indicator: ASN, country, first/last seen, services, tags, ATT&CK, confidence |
| `stix/` · `misp/` · `zeek/` · `suricata/` · `mikrotik/` · `nft/` · `crowdsec/` · `defender/` | The same data, pre-rendered |
| `feed.json` · `SHA256SUMS` · `SHA256SUMS.minisig` | Index, checksums and signature |

Every record follows [`schema/record.schema.json`](schema/record.schema.json), also served at `https://feeds.offseq.com/mirage-feed/schema/record.schema.json`.

## How an IP gets listed

An address appears in the feed only when **all** of these hold:

1. It completed a TCP handshake and sent application data. UDP-only and spoofable traffic never qualifies.
2. At least **3 Mirage sensors in at least 2 networks** saw it within 7 days. One-off hits stay out.
3. It is not a known research scanner, CDN, public resolver, bogon or any range on the
   [MISP warninglists](https://github.com/MISP/misp-warninglists).
4. Its first sighting is at least **24 hours** old.

Entries expire **7 days** after the last observed activity. New activity renews them.

Before every publish, CI refuses the build when any of these checks fail:

- An attacker entry is not a single IPv4 address or IPv6 /64, is duplicated, or overlaps the
  [allowlist](generator/allowlist.txt) (special-purpose ranges, public resolvers, root servers and the first-party
  ranges of Cloudflare, Google, Microsoft 365, Apple, GitHub, Akamai and Fastly) or a [canary address](generator/canary.txt).
- A scanner entry is wider than one address (one /64 or smaller for IPv6), or is also listed as an attacker.
- An IP, URL or domain list changes size by more than 30 % (50 % for `ipv4-1d.txt`) from the previous day.
  Changes under 20 entries are ignored.
- More than 40 % of a 7- or 30-day IP list is new while more than 40 % of the previous day's list is gone.
- One ASN holds more than 15 % of the 7-day list, or one IPv4 /16 more than 5 % (lists of 200 or more entries).
- Any file matches the private leak rules (sensor addresses, decoy hostnames, internal markers).
- A record fails the schema, or the STIX bundle has duplicate ids, missing properties or no TLP:CLEAR marking.

Domains, paths and user agents are filtered as well. Popular sites (Tranco top 10k), code-hosting and file-sharing
services and public suffixes never appear in `domains-7d.txt`, though they can appear inside full URLs. Generic paths
such as `/` and `/robots.txt` and plain browser user agents are dropped.

Most listed addresses are compromised devices or rented infrastructure. A listing means
"this address attacked honeypots", not a judgement about whoever holds it.

## Community feed and full feed

This repository is the community edition. It is free, and it stays free.

| | Community (this repo) | Full feed |
|---|---|---|
| Update cadence | Daily, 24 h delayed | Real time (API, webhook, TAXII) |
| Attacker IPs | Multi-sensor, high confidence | Every source, incl. targeted single-sensor activity |
| Context per IP | ASN, country, tags | Ports, protocols, full session timeline |
| Payloads and commands | URLs and hashes | Decoded payloads, shell transcripts, stage-2 captures |
| Credentials | Top 100 passwords, no usernames | Full corpus of attempted credentials and captured hashes |
| Attribution | — | Actor clusters, campaigns, AI-assisted intent verdicts |
| History | 7–30 days | 365 days |
| Delivery | Files | API, TAXII 2.1, MISP sync, OpenCTI connector |
| Private sensors | — | Mirage honeypots on your own IP space, with alerts |

The full feed is available to OffSeq customers. **[Request a trial →](https://mirage.offseq.com/?utm_source=github&utm_medium=readme&utm_campaign=mirage-feed)**

## Verify a download

Paths in `SHA256SUMS` are relative to the feed root, so download files into the same layout:

```sh
base=https://feeds.offseq.com/mirage-feed
curl -fsSLO "$base/SHA256SUMS" -O "$base/SHA256SUMS.minisig"
minisign -Vm SHA256SUMS -P RWQeu/vC+HeSo+5whq+ViPiKFUe35GOuuVll6WA6QKlFNirw7IzweToA
curl -fsSL --create-dirs -o latest/ipv4-7d.txt "$base/latest/ipv4-7d.txt"
sha256sum -c --ignore-missing SHA256SUMS        # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
```

## False positives and removal

If your address is listed and should not be, use the
[removal form](https://feeds.offseq.com/removal) or write to `abuse@offseq.com`.
No GitHub account needed. Requests are handled within 72 hours. An address that resumes
attacking is listed again.

Bug in a file format or an integration? [Open an issue](https://github.com/offseq/mirage-feed/issues).

## License

Data: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Credit "OffSeq Mirage" with a link
to this repository. Code: MIT. Marked **TLP:CLEAR**.

The data is provided as is, without warranty. You decide what to block.
Privacy notice: [feeds.offseq.com/privacy](https://feeds.offseq.com/privacy).

---

<p align="center">
<a href="https://offseq.com">OffSeq</a> · European offensive security · <a href="https://mirage.offseq.com">Mirage</a> · <a href="https://offseq.com/en/research/">Research</a>
</p>
