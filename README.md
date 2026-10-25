<h1 align="center">Mirage Feed</h1>

<p align="center">
Daily threat intelligence from the <a href="https://mirage.offseq.com">OffSeq Mirage</a> honeypot fleet.<br>
Handshake-verified attacker IPs, exploited CVEs, payload URLs and fingerprints,<br>
in the formats your firewall, SIEM and threat-intel platform already read.
</p>

<p align="center">
<img alt="Feed freshness" src="https://img.shields.io/endpoint?url=https://feeds.offseq.com/badge/freshness.json&style=flat-square">
<img alt="Listed IPs" src="https://img.shields.io/endpoint?url=https://feeds.offseq.com/badge/ips.json&style=flat-square">
<img alt="License CC BY 4.0" src="https://img.shields.io/badge/data-CC%20BY%204.0-0b6e8a?style=flat-square">
<img alt="TLP:CLEAR" src="https://img.shields.io/badge/TLP-CLEAR-ffffff?style=flat-square&labelColor=1f2937">
</p>

---

<!-- stats:start -->
### Today's snapshot

| | Observed by Mirage, last 24 h | In the feed | Feed window |
|---|---:|---:|---|
| Source IPs active in the last 24 h | 7,906 | 789 | 24 h |
| Source IPs | — | 1,688 | 7 days |
| VPN / Tor exits (only in `anonymizers-7d.txt`) | — | 46 | 7 days |
| IPv4 addresses (`ipv4-30d.txt`) | — | 5,232 | 30 days |
| Networks (ASNs) | 718 | 362 | 7 days |
| Countries | 109 | 76 | 7 days |
| CVEs exploited (9 in CISA KEV) | 4 | 10 | 7 days |
| Payload / download URLs | 16 | 9 | 7 days |
| Malware hashes | 15 | 3 | 30 days |
| Tooling fingerprints (JA4, HASSH) | — | 72 | 7 days |
| Research scanners (excluded) | — | 5,412 | 7 days |
| Credential pairs tried | 183,133 | top 100 passwords | 7 days |
| Events | 864.74k events | — | — |

<sub>Snapshot 2026-10-25 18:35 UTC · the observed column counts everything the fleet saw in the 24 h before the snapshot; the feed column counts what passed the listing rules over the window shown · entries are published 24 h after first sighting · <a href="#how-an-ip-gets-listed">methodology</a></sub>
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

### Which list do I want?

| You want to | Use |
|---|---|
| Block attackers on a firewall | `ipv4-7d.txt`, plus `ipv6-7d.txt` if you route IPv6 |
| Block on a device with a small table | `ipv4-top1k.txt` or `ipv4-top10k.txt`: the 1,000 or 10,000 highest-confidence addresses (file sorted by address) |
| Block only what is active right now | `ipv4-1d.txt` |
| Alert or enrich with a longer memory | `ipv4-30d.txt` (better for detection than for blocking) |
| Review what changed since yesterday | `ipv4-added-1d.txt` and `ipv4-removed-1d.txt` |
| Flag VPN and Tor exits seen attacking | `anonymizers-7d.txt`. Shared by many users, so enrich with it, don't block it |
| Enrich SIEM events with context | `attackers-7d.csv` or `records-7d.ndjson.gz` |
| Import into a threat-intel platform | `stix/mirage.json` or the MISP feed |
| Hunt in web server logs | `user-agents-7d.txt` and `paths-7d.txt` |

### Schedule and polling

The feed is built once a day at **03:17 UTC** and entries appear **24 hours** after their first sighting.
Poll at most once an hour; once a day after 03:30 UTC is enough. `feeds.offseq.com` answers `If-None-Match`
(ETag) and `If-Modified-Since` with `304 Not Modified`, so unchanged files cost nothing to re-check.
`history.json` holds 90 days of daily totals, and format changes are listed in [CHANGELOG.md](CHANGELOG.md).

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

Suricata IP reputation: `latest/suricata/categories.txt` and `latest/suricata/mirage-iprep.list`. Every listed
address has a score from 1 to 127 (confidence × 1.27), so `>,0` matches any of them:

```
alert ip any any -> $HOME_NET any (msg:"Mirage feed: known attacker"; iprep:src,MirageAttacker,>,0; threshold:type limit,track by_src,count 1,seconds 3600; classtype:misc-attack; sid:1900001; rev:2;)
```

To alert only on high-confidence addresses (confidence 64 and up), raise the threshold:

```
alert ip any any -> $HOME_NET any (msg:"Mirage feed: high-confidence attacker"; iprep:src,MirageAttacker,>,80; threshold:type limit,track by_src,count 1,seconds 3600; classtype:misc-attack; sid:1900005; rev:1;)
```

`latest/suricata/mirage.rules` holds the first rule plus alert-only, rate-limited hunting rules for attacker
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
  [`docs/opencti-csv-mapper.json`](docs/opencti-csv-mapper.json). The file leaves out addresses without a known ASN,
  which the mapper cannot link; they are in `attackers-7d.csv` and the STIX bundle. Or import `latest/stix/mirage.json`
  as a file.
- **Microsoft Sentinel**: the Upload Indicators API takes at most 100 objects per request, wrapped as
  `{"sourcesystem": "OffSeq Mirage", "stixobjects": [...]}`. [`scripts/sentinel-upload.sh`](scripts/sentinel-upload.sh)
  splits `latest/stix/mirage.json` that way.
- **Defender for Endpoint**: import `latest/defender/defender-top500.csv` (one CSV import batch): the 500
  highest-confidence IPv4 addresses, leaving out VPN/Tor exits and records whose only tag is `web-scan`.
  Rows with Severity Low import with `GenerateAlert` set to False.
- **Splunk**: upload `latest/attackers-7d.csv` as the lookup table file `mirage_attackers.csv`. Its key column is
  `ip`: `... | lookup mirage_attackers.csv ip AS src_ip OUTPUT confidence tags as_org`.
</details>

## What's in the feed

| File | Contents |
|---|---|
| `ipv4-{1d,7d,30d}.txt` | Attacker IPv4 addresses by activity window |
| `ipv4-top{1k,10k}.txt` | The 1,000 or 10,000 highest-confidence addresses (file sorted by address), sized for capped firewall tables |
| `ipv4-7d-cidr32.txt` · `ipv6-7d.txt` | IPv4 with `/32` suffix (AWS WAF IP sets) and IPv6 `/64` networks |
| `ipv4-added-1d.txt` · `ipv4-removed-1d.txt` | Addresses that entered `ipv4-7d.txt` since the previous day's build, and every address that left it: aged out, removed on request, newly allowlisted or now a VPN/Tor exit. Unblock what is in the removed list |
| `anonymizers-7d.txt` | VPN and Tor exits that attacked the fleet (IPv4 and IPv6 `/64`). Kept out of every block list and rule file |
| `known-scanners-ipv4.txt` · `known-scanners-ipv6.txt` | Research scanners we saw and **excluded** (Shodan, Censys, Shadowserver …). Allowlist these if you like. |
| `urls-7d.txt` · `domains-7d.txt` | Payload, dropper and C2 locations from captured exploit attempts |
| `hashes-sha256-30d.txt` | Files those payloads delivered |
| `cves-7d.csv` | CVEs exploited against the fleet in the last 7 days, with CISA KEV flag and attempt counts. Lists every CVE on a 7-day IP record; the KEV flag comes from the [CISA catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), vendored in [`generator/kev.txt`](generator/kev.txt) |
| `fingerprints.csv` · `hassh.csv` | JA4 TLS client fingerprints and SSH HASSH of attacker tooling |
| `user-agents-7d.txt` · `paths-7d.txt` | Distinctive HTTP user agents and request paths seen in attacks. For hunting, not blocking |
| `passwords-top100.txt` | The 100 passwords attackers tried most, without usernames |
| `attackers-7d.csv` · `attackers-ipv4-7d.csv` · `records-7d.ndjson.gz` | One record per indicator: ASN, country, first/last seen, services, tags, ATT&CK, confidence |
| `stix/` · `misp/` · `zeek/` · `suricata/` · `mikrotik/` · `nft/` · `crowdsec/` · `defender/` | The same data, pre-rendered |
| `history.json` | Daily totals for the last 90 days, no addresses |
| `og.png` · `og-github.png` | Social preview images of the day's numbers |
| `lookup/v4/<first octet>.json` · `lookup/v6/<first hextet>.json` | Every listed address grouped for the [address lookup](https://feeds.offseq.com/ip), with its lists and record. Listed in `SHA256SUMS`, and as one `latest/lookup/` entry in `feed.json` |
| `feed.json` · `SHA256SUMS` · `SHA256SUMS.minisig` | Index with `schema_version`, checksums of every file (including `feed.json`) and signature |

Every record follows [`schema/record.schema.json`](schema/record.schema.json), also served at `https://feeds.offseq.com/mirage-feed/schema/record.schema.json`.

## How an IP gets listed

An address appears in the feed only when **all** of these hold:

1. It completed a TCP handshake and sent application data. UDP-only and spoofable traffic never qualifies.
2. At least **3 Mirage sensors in at least 2 networks** saw it within 7 days. One-off hits stay out.
3. It is not in the [allowlist](generator/allowlist.txt): private and special-purpose ranges (RFC 1918, RFC 3849,
   RFC 5735, RFC 6598, RFC 6890, multicast, IPv6 link-local), public DNS resolvers and root servers, and the
   first-party ranges of Cloudflare, Akamai (without Linode), Fastly, Apple and Microsoft 365 from the vendored
   [MISP warninglists](https://github.com/MISP/misp-warninglists), Google's own ranges (not Google Cloud), GitHub and
   Microsoft's AS8068 edge. Customer clouds (AWS, Azure, Google Cloud, Linode) are not excluded: that is where
   attackers rent machines.
4. It is not a known research scanner: Alpha Strike, BinaryEdge, Bitsight, Censys, Criminal IP, Cyber Resilience,
   Driftnet, FOFA, Hadrian, Internet Census, Internet Measurement, Intrinsec, IPIP, LeakIX, Modat, Netlas, NETSCOUT,
   ONYPHE, Palo Alto Xpanse, Quake, Rapid7, ReCyber, Shadowserver, Shodan, Stretchoid, Tenable, ZoomEye, university
   research networks and scanners that name themselves in their user agent. These go to `known-scanners-*.txt`.
5. Its first sighting is at least **24 hours** old.

VPN and Tor exits (records tagged `vpn-exit` or `tor-exit`) are listed only in `anonymizers-7d.txt` and in the
full-record formats, where the tag shows: CSV and NDJSON, MISP as `ip-src` with `to_ids: false`, and STIX as
`anonymization` indicators rather than `malicious-activity`. They never reach a block list or rule file.

Entries expire **7 days** after the last observed activity. New activity renews them.

Before every publish, CI refuses the build when any of these checks fail:

- An attacker entry is not a single IPv4 address or IPv6 /64, is duplicated, or overlaps the
  [allowlist](generator/allowlist.txt) (special-purpose ranges, public resolvers, root servers and the first-party
  ranges of Cloudflare, Google, Microsoft 365, Apple, GitHub, Akamai and Fastly) or a [canary address](generator/canary.txt).
- A scanner entry is wider than one address (one /64 or smaller for IPv6), or is also listed as an attacker.
- An IP, URL or domain list changes size by more than 30 % (50 % for `ipv4-1d.txt`) from the previous day.
  Changes under 20 entries are ignored.
- More than 40 % of a 7- or 30-day IP list is new while more than 40 % of the previous day's list is gone.
- One ASN holds more than 25 % of the 7-day list and more than 10 points over its share in the previous build, or one
  IPv4 /16 holds more than 5 % and more than 5 points over its previous share (lists of 200 or more entries).
- A VPN or Tor exit from `anonymizers-7d.txt` appears in any block list, firewall script, Suricata or Zeek file, the
  Defender CSV, a MISP `ip-src` with `to_ids` set or a STIX `malicious-activity` indicator.
- `ipv4-added-1d.txt` lists an address that is not in `ipv4-7d.txt`, or `ipv4-removed-1d.txt` one that still is.
- The snapshot is older than the published build (a rollback needs an explicit override; re-running the same snapshot republishes identical files).
- A Defender row or STIX indicator would already be expired on import.
- The lookup files under `lookup/` do not hold exactly the addresses of the IP lists, each with its lists.
- Any file matches the private leak rules (sensor addresses, decoy hostnames, internal markers).
- A record fails the schema, or the STIX bundle has duplicate ids, missing properties or no TLP:CLEAR marking.

Domains, paths and user agents are filtered as well:

- **Domains**: popular sites (Tranco top 10k), code-hosting and file-sharing services and public suffixes never
  appear in `domains-7d.txt`, though they can appear inside full URLs.
- **User agents**: only distinctive attack-tool strings are kept. Dropped are browser strings (every product token is
  a browser one, such as `Mozilla`, `AppleWebKit`, `Chrome`, `Safari`, `Firefox`, `Edg` or `OPR`, including a bare
  `Mozilla/5.0`), HTTP libraries (`curl`, `Wget`, `python-requests`, `Go-http-client`, `okhttp`, `axios`,
  `node-fetch`, `Java`, `libwww-perl`, `VLC` and similar) and anything that names itself a bot, crawler, spider,
  scanner or research project or carries a contact URL or address. Named attack tools (zgrab, masscan, nuclei,
  sqlmap, gobuster, SIPVicious `friendly-scanner` and others) are kept even when they say "scanner".
- **Paths**: dropped are `/`, `/robots.txt`, `/.well-known/*` and common legitimate endpoints (login, admin, API,
  GraphQL, health, sitemap, WordPress login and AJAX, Exchange autodiscover, VPN portal start pages, MCP and others)
  in their simple variants, plus any path with an `@` (other than `/@vite/`), a hex or base64 run of 16 or more
  characters or a `/s/<token>/` segment, because those encode the scanned target. The Suricata path dataset is
  stricter still: it only holds paths tied to a CVE or with an exploit pattern (traversal, `;`, `%2e`, `${`,
  `cgi-bin`, `/etc/passwd`, shell metacharacters after `.php?` and known device exploit paths).

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
| Attribution | — | Actor clusters, campaigns, AI intent verdicts |
| History | 7–30 days | 365 days |
| Analysis | — | Ask Mirage natural-language queries |
| Exports | Daily files | STIX, MISP, CSV on demand |

The full feed is available to OffSeq customers. **[Request a trial →](https://mirage.offseq.com/?auth=signup&intent=premium&utm_source=github&utm_medium=readme&utm_campaign=mirage-feed)**

## Verify a download

Paths in `SHA256SUMS` are relative to the feed root, so download files into the same layout:

```sh
base=https://feeds.offseq.com/mirage-feed
curl -fsSLO "$base/SHA256SUMS" -O "$base/SHA256SUMS.minisig"
minisign -Vm SHA256SUMS -P RWQeu/vC+HeSo+5whq+ViPiKFUe35GOuuVll6WA6QKlFNirw7IzweToA   # check the trusted comment
curl -fsSL --create-dirs -o latest/ipv4-7d.txt "$base/latest/ipv4-7d.txt"
sha256sum -c --ignore-missing SHA256SUMS        # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
```

The trusted comment reads `mirage-feed <day> generated <build time>` and is covered by the signature: check that the
build time is recent, so a mirror cannot pass off an old signed build as today's. The minisign public key is also
published at `https://feeds.offseq.com/.well-known/mirage-feed-minisign.pub`. `SHA256SUMS` carries a GitHub build-provenance
attestation; check that it came from this repository's publish workflow on `main`:

```sh
gh attestation verify SHA256SUMS -R offseq/mirage-feed --signer-workflow offseq/mirage-feed/.github/workflows/publish.yml --source-ref refs/heads/main
```

[`scripts/check-feed.sh`](scripts/check-feed.sh) runs all of this (signature, checksums, freshness and format) in
one go.

## If this blocks something you need

Allow the address locally first, so you are not waiting on us: put it in an exception alias or add an allow rule
above the block rule. Then ask for removal through the
[removal form](https://feeds.offseq.com/removal) or at `abuse@offseq.com`. No GitHub account needed. Requests are
handled within 72 hours and take effect in the next daily build. An address that resumes attacking is listed again.

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
