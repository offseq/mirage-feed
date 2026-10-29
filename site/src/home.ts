import { lookupForm } from "./lookup";
import { ABUSE, BASE, ISO, REPO_URL, SITE, bytes, cmd, copyable, esc, num, pre, upsell, utc } from "./html";

type Counts = Partial<Record<string, number>>;

export interface Stats {
  observed?: Counts;
  published?: Counts;
  attack?: { technique: string; name?: string; ips?: number; events?: number }[];
  services?: { service: string; ips?: number }[];
  countries?: { country: string; ips?: number }[];
}

export interface FeedEntry {
  path: string;
  format?: string;
  window?: string;
  count?: number;
  bytes?: number;
  sha256?: string;
  consumers?: string[];
}

export interface FeedIndex {
  generated?: string;
  day?: string;
  policy?: { min_sensors?: number; min_networks?: number; delay_hours?: number; ttl_days?: number };
  stats?: Stats;
  mirrors?: (string | { url?: string; name?: string })[];
  files?: FeedEntry[];
}

export const MINISIGN_PUBKEY = "RWQeu/vC+HeSo+5whq+ViPiKFUe35GOuuVll6WA6QKlFNirw7IzweToA";

const SUBSCRIBE: [string, string][] = [
  ["IPv4 blocklist, last 7 days", "latest/ipv4-7d.txt"],
  ["IPv4 top 1,000, for small firewall tables", "latest/ipv4-top1k.txt"],
  ["Payload and C2 URLs", "latest/urls-7d.txt"],
  ["Malware SHA-256", "latest/hashes-sha256-30d.txt"],
  ["Full records, CSV", "latest/attackers-7d.csv"],
  ["STIX 2.1 bundle", "latest/stix/mirage.json"],
  ["MISP feed, add as a MISP Feed", "misp/"],
  ["Research scanners we excluded, IPv4", "latest/known-scanners-ipv4.txt"],
  ["VPN and Tor exits seen attacking, kept out of the blocklists", "latest/anonymizers-7d.txt"],
  ["IPv4 added since the previous build", "latest/ipv4-added-1d.txt"],
  ["IPv4 removed since the previous build", "latest/ipv4-removed-1d.txt"],
];

const STAT_ROWS: [string, string | null, string | null][] = [
  ["Source IPs", "ips", "ips"],
  ["Networks (ASNs)", "asns", "asns"],
  ["Countries", "countries", "countries"],
  ["CVEs exploited", "cves", "cves"],
  ["Payload and C2 URLs", "urls", "urls"],
  ["Malware hashes", "hashes", "hashes"],
  ["Credential pairs tried", "credential_pairs", null],
  ["Events", "events", null],
  ["Research scanners excluded", null, "scanners"],
  ["Tool fingerprints", null, "fingerprints"],
];
const IPS_30D: [string, string | null, string | null] = ["IPv4, 30-day list", null, "ips_30d"];

const cell = (c: Counts | undefined, key: string | null) =>
  key === null ? '<td class="n dim">-</td>' : `<td class="n">${num(c?.[key])}</td>`;

let regionNames: Intl.DisplayNames | null = null;
function country(code: string): string {
  try {
    regionNames ??= new Intl.DisplayNames(["en"], { type: "region" });
    return regionNames.of(code) ?? code;
  } catch {
    return code;
  }
}

const TOP_N = 8;

function bars(title: string, all: { label: string; value: number }[]): string {
  const rows = [...all].sort((a, b) => b.value - a.value).slice(0, TOP_N);
  if (!rows.length) return "";
  const max = Math.max(...rows.map((r) => r.value), 1);
  const body = rows
    .map((r) => {
      const w = ((r.value / max) * 100).toFixed(2);
      return `<tr><td>${r.label}</td><td class="bar"><svg viewBox="0 0 100 1" preserveAspectRatio="none" aria-hidden="true"><rect class="t" width="100" height="1"/><rect class="v" width="${w}" height="1"/></svg></td><td class="n">${num(r.value)}</td></tr>`;
    })
    .join("");
  return `<div><h3>${esc(title)}</h3><table><thead><tr><th scope="col"><span class="sr">Item</span></th><th scope="col"><span class="sr">Share</span></th><th scope="col" class="n">IPs</th></tr></thead><tbody>${body}</tbody></table></div>`;
}

export const technique = (id: string, name?: string): string =>
  name && name !== id ? `${esc(id)} <span class="dim">${esc(name.startsWith(`${id} `) ? name.slice(id.length + 1) : name)}</span>` : esc(id);

function gapBar(active: number, observed: number): string {
  const pct = Math.min(active / observed, 1);
  const share = (pct * 100).toFixed(1);
  const label = `${num(active)} of ${num(observed)} source IPs seen in the last 24 hours are in the feed, ${share} percent`;
  return `<svg class="gap" role="img" aria-label="${esc(label)}">
<defs><pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><line class="hl" x1="0" y1="0" x2="0" y2="6"/></pattern></defs>
<rect class="obs" width="100%" height="100%"/><rect class="pub" width="${(pct * 100).toFixed(2)}%" height="100%"/></svg>
<div class="legend"><span><i aria-hidden="true"></i>in the feed ${share}%</span><span><i class="h" aria-hidden="true"></i>seen, not in the feed</span></div>`;
}

function headline(obs: Counts, pub: Counts, stale: boolean): string {
  const window = stale ? "in the 24 hours before this build" : "in the last 24 hours";
  const active = pub.active_24h;
  const seen = obs.ips;
  if (typeof active !== "number" || typeof seen !== "number" || seen <= 0) {
    return `<p class="big">${num(pub.ips)}</p>\n<p class="lede">source IPs in the 7-day feed</p>`;
  }
  return `<p class="big">${num(Math.min(active, seen))}</p>
<p class="lede">of ${num(seen)} source IPs seen ${window} are in the feed</p>
${gapBar(active, seen)}
<p>Every address Mirage saw attacking ${window} counts as seen. Those in the feed have passed the <a href="#methodology">listing rules</a>. The gap is what the <a href="${esc(upsell("status"))}">full feed</a> holds.</p>`;
}

function status(feed: FeedIndex | null, stats: Stats | null, stale: boolean): string {
  const obs = stats?.observed;
  const pub = stats?.published;
  if (!obs || !pub) {
    return `<div class="empty"><p>No snapshot yet.</p><p>Counts appear here after the first daily build is published. The file paths below are already final.</p></div>`;
  }
  const when = [feed?.day ? `Snapshot of ${esc(feed.day)}` : "", feed?.generated ? `built ${esc(utc(feed.generated))}` : ""]
    .filter(Boolean)
    .join(", ");
  const statRows = typeof pub.ips_30d === "number" ? [...STAT_ROWS.slice(0, 1), IPS_30D, ...STAT_ROWS.slice(1)] : STAT_ROWS;
  const rows = statRows.map(([label, o, p]) => `<tr><th scope="row">${label}</th>${cell(obs, o)}${cell(pub, p)}</tr>`).join("");
  const tops = [
    bars("ATT&CK techniques", (stats.attack ?? []).map((a) => ({ label: technique(a.technique, a.name), value: a.ips ?? 0 }))),
    bars("Services", (stats.services ?? []).map((s) => ({ label: esc(s.service), value: s.ips ?? 0 }))),
    bars(
      "Countries",
      (stats.countries ?? []).map((c) => ({ label: `${esc(c.country)} <span class="dim">${esc(country(c.country))}</span>`, value: c.ips ?? 0 })),
    ),
  ].join("");
  return `${when ? `<p class="dim">${when}.</p>` : ""}
${headline(obs, pub, stale)}
<div class="scroll" tabindex="0" role="region" aria-label="Counts for the last 24 hours and in the feed"><table><thead><tr><td></td><th scope="col" class="n">Last 24 h</th><th scope="col" class="n">In the feed</th></tr></thead><tbody>${rows}</tbody></table></div>
<p class="dim">Feed lists cover the last 7 days of activity (30 days for <code>ipv4-30d.txt</code>).</p>
${tops ? `<div class="tops">${tops}</div>` : ""}`;
}

export const STALE_AFTER_H = 36;

// Same threshold as /status.json and the freshness badge, which compare in seconds, not whole hours.
function staleHours(feed: FeedIndex | null, now: number): number | null {
  const age = now - Date.parse(feed?.generated ?? "");
  return Number.isFinite(age) && age > STALE_AFTER_H * 3_600_000 ? Math.floor(age / 3_600_000) : null;
}

function staleNotice(feed: FeedIndex | null, hours: number | null): string {
  if (hours === null) return "";
  const age = hours >= 72 ? `${Math.floor(hours / 24)} days` : `${hours} hours`;
  return `<p class="msg err">Stale: this snapshot was built ${esc(utc(feed!.generated!))}, ${age} ago. A daily build is overdue. The lists still load, but they are not current.</p>\n`;
}

function files(feed: FeedIndex | null): string {
  // The lookup shards appear as one directory entry; they serve the address lookup, not subscribers.
  const list = (feed?.files ?? []).filter((f) => !f.path?.endsWith("/"));
  if (!list.length) {
    return `<div class="empty"><p>The file index is generated with each daily build and is not published yet.</p></div>`;
  }
  const rows = list
    .map(
      (f) => `<tr><td class="nw"><a href="/mirage-feed/${esc(f.path)}">${esc(f.path)}</a>${f.consumers?.length ? `<span class="used">${esc(f.consumers.join(", "))}</span>` : ""}</td><td class="n">${num(f.count)}</td><td class="n">${bytes(f.bytes)}</td><td class="nw"><a href="/mirage-feed/SHA256SUMS" aria-label="SHA-256 ${esc(f.sha256 ?? "")}, full list in SHA256SUMS"><abbr title="${esc(f.sha256 ?? "")}">${esc((f.sha256 ?? "").slice(0, 12))}</abbr></a></td></tr>`,
    )
    .join("");
  // Mirrors are URL prefixes for the same paths, not browsable pages.
  const mirrors = (feed?.mirrors ?? [])
    .map((m) => (typeof m === "string" ? m : (m.url ?? "")))
    .filter((u) => /^https:\/\//.test(u) && !u.startsWith(SITE))
    .map((u) => `<code>${esc(u)}</code>`)
    .join(", ");
  return `<div class="scroll" tabindex="0" role="region" aria-label="File index"><table><thead><tr><th scope="col">path <span class="dim">and tools that read it</span></th><th scope="col" class="n">count</th><th scope="col" class="n">size</th><th scope="col">sha256</th></tr></thead><tbody>${rows}</tbody></table></div>
<p class="dim">Full checksums in <a href="/mirage-feed/SHA256SUMS">SHA256SUMS</a>. Index as JSON: <a href="/mirage-feed/feed.json">feed.json</a>.${mirrors ? ` Mirrors: ${mirrors}.` : ""}</p>
<p><code>anonymizers-7d.txt</code> lists VPN and Tor exits seen attacking; they stay out of the blocklists because many people share them. <code>ipv4-added-1d.txt</code> and <code>ipv4-removed-1d.txt</code> hold the day-over-day change to <code>ipv4-7d.txt</code>, for change review.</p>`;
}

const recipe = (title: string, body: string) => `<details><summary>${title}</summary>${body}</details>`;

function integrations(): string {
  const ip7 = `${BASE}/latest/ipv4-7d.txt`;
  return [
    recipe(
      "pfSense / OPNsense",
      `<p>Firewall &gt; Aliases &gt; Add. Type <b>URL Table (IPs)</b>, URL ${copyable(ip7, "pfSense URL")}, refresh <b>1 day</b>. Use the alias as the source of a block rule on WAN.</p>`,
    ),
    recipe(
      "FortiGate",
      pre(`config system external-resource
    edit "mirage-feed"
        set type address
        set resource "${ip7}"
        set refresh-rate 1440
    next
end`, "FortiGate configuration"),
    ),
    recipe(
      "Palo Alto (EDL)",
      `<p>Objects &gt; External Dynamic Lists &gt; Add. Type <b>IP List</b>, source ${copyable(ip7, "EDL URL")}, repeat <b>Daily</b>. Firewalls with a 50k EDL budget should use <code>ipv4-top1k.txt</code> or <code>ipv4-top10k.txt</code>.</p>`,
    ),
    recipe(
      "MikroTik RouterOS",
      pre(`/tool fetch url="${BASE}/latest/mikrotik/mirage-7d.rsc" dst-path=mirage.rsc
/import file-name=mirage.rsc`, "RouterOS commands") + `<p>Entries carry <code>timeout=7d</code>, so they expire on their own.</p>`,
    ),
    recipe(
      "nftables / ipset",
      `<p>nftables:</p>` +
        pre(`curl --create-dirs -fsSLo /etc/nftables.d/mirage.nft ${BASE}/latest/nft/mirage.nft
nft -f /etc/nftables.d/mirage.nft`, "nftables commands") +
        `<p>ipset with iptables, safe to re-run:</p>` +
        pre(`curl -fsSL ${BASE}/latest/ipset/mirage.ipset | ipset restore
iptables -C INPUT -m set --match-set mirage4 src -j DROP 2>/dev/null \\
  || iptables -I INPUT -m set --match-set mirage4 src -j DROP
ip6tables -C INPUT -m set --match-set mirage6 src -j DROP 2>/dev/null \\
  || ip6tables -I INPUT -m set --match-set mirage6 src -j DROP`, "ipset commands"),
    ),
    recipe(
      "CrowdSec",
      pre(`curl -fsSL ${ip7} -o mirage.txt
cscli decisions import -i mirage.txt --format values --duration 48h --scope ip --reason mirage-feed`, "CrowdSec commands"),
    ),
    recipe(
      "Suricata and Zeek",
      `<p>Suricata IP reputation: <code>latest/suricata/categories.txt</code> and <code>latest/suricata/mirage-iprep.list</code>.</p>` +
        pre(`alert ip any any -> $HOME_NET any (msg:"Mirage feed: known attacker"; iprep:src,MirageAttacker,>,0; threshold:type limit,track by_src,count 1,seconds 3600; classtype:misc-attack; sid:1900001; rev:2;)`, "Suricata rule") +
        `<p>Scores are confidence × 1.27, so <code>&gt;,80</code> keeps only confidence 64 and up.</p>` +
        `<p>Zeek Intel framework, with <code>latest/zeek/mirage.intel</code> saved locally:</p>` +
        pre(`redef Intel::read_files += { "/opt/mirage/mirage.intel" };`, "Zeek configuration"),
    ),
    recipe(
      "MISP, OpenCTI, Sentinel, Defender, Splunk",
      `<ul>
<li><b>MISP</b>: Sync Actions &gt; Feeds &gt; Add. Source format <b>MISP Feed</b>, URL ${copyable(`${BASE}/misp/`, "MISP feed URL")}.</li>
<li><b>OpenCTI</b>: Data &gt; Ingestion &gt; CSV feeds on <code>latest/attackers-ipv4-7d.csv</code>, with the mapper in the <a href="${REPO_URL}">repository</a> under <code>docs/opencti-csv-mapper.json</code>. Or import <code>latest/stix/mirage.json</code> as a STIX bundle.</li>
<li><b>Microsoft Sentinel</b>: the Upload Indicators API takes at most 100 objects per request, wrapped as <code>{"sourcesystem": "OffSeq Mirage", "stixobjects": [...]}</code>. <a href="${REPO_URL}/blob/main/scripts/sentinel-upload.sh">scripts/sentinel-upload.sh</a> splits <code>latest/stix/mirage.json</code> that way:${pre("WORKSPACE_ID=<workspace id> scripts/sentinel-upload.sh mirage.json", "Sentinel upload command")}</li>
<li><b>Defender for Endpoint</b>: Settings &gt; Endpoints &gt; Indicators &gt; Import, with <code>latest/defender/defender-top500.csv</code>. The import takes 500 indicators per batch, which is why the file stops at 500.</li>
<li><b>Splunk</b>: add <code>latest/attackers-7d.csv</code> as a lookup and match its <code>ip</code> column against <code>src_ip</code>.</li>
</ul>`,
    ),
  ].join("\n");
}

export function renderHome(feed: FeedIndex | null, stats: Stats | null, now: number): string {
  const p = feed?.policy ?? {};
  const sensors = p.min_sensors ?? 3;
  const networks = p.min_networks ?? 2;
  const delay = p.delay_hours ?? 24;
  const ttl = p.ttl_days ?? 7;
  const subscribe = SUBSCRIBE.map(([use, path]) => `<tr><td>${use}</td><td>${copyable(`${BASE}/${path}`, use)}</td></tr>`).join("");

  const hours = staleHours(feed, now);
  return `<h1 class="sr">Mirage Feed: daily honeypot threat intelligence from OffSeq</h1>
${staleNotice(feed, hours)}<section aria-labelledby="h-name"><h2 id="h-name">Name</h2>
<p class="name"><b>mirage-feed</b> - daily attacker indicators from the OffSeq Mirage honeypot fleet</p>
<p>Handshake-verified attacker IPs, exploited CVEs, payload URLs and tool fingerprints, rebuilt every day in the formats firewalls, SIEMs and threat-intel platforms already read. Free to use under CC BY 4.0, marked TLP:CLEAR.</p>
<p>Need it in real time, with full session context? That is the <a href="${esc(upsell("hero"))}">full feed in OffSeq Mirage</a>.</p>
</section>

<section aria-labelledby="h-synopsis"><h2 id="h-synopsis">Synopsis</h2>
${cmd(`curl -fsSL ${BASE}/latest/ipv4-7d.txt`, "curl command")}
<p class="dim">One address per line, no comments. Paths are stable; contents change daily.</p>
</section>

<section id="status" aria-labelledby="h-status"><h2 id="h-status">Status</h2>
${status(feed, stats, hours !== null)}
</section>

<section id="lookup" aria-labelledby="h-lookup"><h2 id="h-lookup">Look up an address</h2>
${lookupForm()}
<p class="dim">Shows whether the address is in today's lists, and why.</p>
</section>

<section id="subscribe" aria-labelledby="h-subscribe"><h2 id="h-subscribe">Subscribe</h2>
<p>Point your tool at a stable URL. Files are rebuilt every day; the paths never change.</p>
<div class="scroll"><table><thead><tr><th scope="col">Use</th><th scope="col">URL</th></tr></thead><tbody>${subscribe}</tbody></table></div>
<p>Plain lists hold one value per line with no comments, so they load as-is into pfBlockerNG, OPNsense aliases, FortiGate threat feeds and Palo Alto EDLs.</p>
<h3>Which list do I want?</h3>
<ul>
<li>A firewall or EDL with room to spare: <code>ipv4-7d.txt</code>, plus <code>ipv6-7d.txt</code> if you filter IPv6.</li>
<li>A small table, such as a 50k EDL budget or a home router: <code>ipv4-top1k.txt</code> or <code>ipv4-top10k.txt</code>.</li>
<li>Only the most recent attackers: <code>ipv4-1d.txt</code>. Longer memory for detection rather than blocking: <code>ipv4-30d.txt</code>.</li>
<li>A SIEM or threat-intel platform: <code>attackers-7d.csv</code>, the STIX bundle or the MISP feed, which carry ASN, tags, ATT&amp;CK and CVEs.</li>
<li>Enrichment, not blocking: <code>anonymizers-7d.txt</code> and <code>known-scanners-ipv4.txt</code>.</li>
</ul>
</section>

<section id="files" aria-labelledby="h-files"><h2 id="h-files">Files</h2>
${files(feed)}
</section>

<section id="integrate" aria-labelledby="h-integrate"><h2 id="h-integrate">Integration</h2>
${integrations()}
</section>

<section id="methodology" aria-labelledby="h-method"><h2 id="h-method">How an IP gets listed</h2>
<p>An address is published only when <b>all</b> of these hold:</p>
<ol>
<li>It completed a TCP handshake and sent application data. UDP-only and spoofable traffic never qualifies.</li>
<li>At least <b>${sensors} Mirage sensors in at least ${networks} networks</b> saw it within ${ttl} days. One-off hits stay out.</li>
<li>It is not a known research scanner and not in the <a href="${REPO_URL}/blob/main/generator/allowlist.txt">allowlist</a>: private and special-purpose ranges, public DNS resolvers, root servers, and the first-party ranges of Cloudflare, Akamai, Fastly, Google, Microsoft 365, Apple and GitHub, and the published crawler ranges of Google, Bing and OpenAI.</li>
<li>Its first sighting is at least <b>${delay} hours</b> old.</li>
</ol>
<p>Entries expire <b>${ttl} days</b> after the last observed activity; new activity renews them. Research scanners are excluded from the blocklists and published separately in <code>known-scanners-ipv4.txt</code> and <code>known-scanners-ipv6.txt</code>, so you can allowlist them.</p>
<p>Before every publish, the build is rejected if the list overlaps an allowlist, holds any entry other than one IPv4 address (/32) or one IPv6 /64, or changes size by more than 30% from the previous day (50% for <code>ipv4-1d.txt</code>).</p>
<p>Most listed addresses are compromised devices or rented infrastructure. A listing means &quot;this address attacked honeypots&quot;, not a judgement about whoever holds it.</p>
</section>

<section id="full-feed" aria-labelledby="h-full"><h2 id="h-full">Community feed and full feed</h2>
<p>This feed is free and stays free. The full feed is part of OffSeq Mirage.</p>
<div class="scroll" tabindex="0" role="region" aria-label="Community and full feed compared"><table><thead><tr><td></td><th scope="col">Community</th><th scope="col">Full feed</th></tr></thead><tbody>
<tr><th scope="row">Cadence</th><td>Daily, ${delay} h delayed</td><td>Real time: API, webhook, TAXII</td></tr>
<tr><th scope="row">Attacker IPs</th><td>Multi-sensor, high confidence</td><td>Every source, incl. targeted single-sensor activity</td></tr>
<tr><th scope="row">Context per IP</th><td>ASN, country, tags</td><td>Ports, protocols, full session timeline</td></tr>
<tr><th scope="row">Payloads</th><td>URLs and hashes</td><td>Decoded payloads, shell transcripts, stage-2 captures</td></tr>
<tr><th scope="row">Credentials</th><td>Top 100 passwords, no usernames</td><td>Attempted credentials and captured hashes</td></tr>
<tr><th scope="row">Attribution</th><td class="dim">-</td><td>Actor clusters, campaigns, AI intent verdicts</td></tr>
<tr><th scope="row">History</th><td>7 to 30 days</td><td>365 days</td></tr>
<tr><th scope="row">Analysis</th><td class="dim">-</td><td>Ask Mirage natural-language queries</td></tr>
<tr><th scope="row">Exports</th><td>Daily files</td><td>STIX, MISP, CSV on demand</td></tr>
</tbody></table></div>
<a class="cta" href="${esc(upsell("compare"))}">Sign up at mirage.offseq.com</a>
</section>

<section id="verify" aria-labelledby="h-verify"><h2 id="h-verify">Verify a download</h2>
<p>Every build ships <code>SHA256SUMS</code> and a minisign signature over it.</p>
<p>Download into the same paths as the feed, so the names match the checksum file:</p>
${pre(`curl -fsSLO ${BASE}/SHA256SUMS -O ${BASE}/SHA256SUMS.minisig
curl --create-dirs -fsSLo latest/ipv4-7d.txt ${BASE}/latest/ipv4-7d.txt
minisign -Vm SHA256SUMS -P ${MINISIGN_PUBKEY}
sha256sum -c --ignore-missing SHA256SUMS`, "Verification commands")}
<p>minisign prints the signed trusted comment, <code>mirage-feed &lt;day&gt; generated &lt;build time&gt;</code>. Check that the build time is recent, so an old signed build cannot pass as today's.</p>
<p class="dim">On macOS, use <code>shasum -a 256 -c</code> in place of <code>sha256sum -c</code>. The public key is also published at <a href="/.well-known/mirage-feed-minisign.pub">/.well-known/mirage-feed-minisign.pub</a> and in the <a href="${REPO_URL}">repository</a>.</p>
</section>

<section id="removal" aria-labelledby="h-removal"><h2 id="h-removal">Removal</h2>
<p>If your address is listed and should not be, use the <a href="/removal">removal form</a> or write to <a href="mailto:${ABUSE}">${ABUSE}</a>. No GitHub account needed. Requests are handled within 72 hours. An address that resumes attacking is listed again.</p>
<p>A bug in a file format or an integration? <a href="${REPO_URL}/issues">Open an issue</a>.</p>
</section>

<section aria-labelledby="h-see"><h2 id="h-see">See also</h2>
<p><a href="/privacy">privacy</a>, <a href="${REPO_URL}">github.com/offseq/mirage-feed</a>, <a href="/mirage-feed/schema/record.schema.json">record.schema.json</a>, <a href="https://offseq.com/en/research/">OffSeq research</a>, <a href="https://www.first.org/tlp/">FIRST TLP 2.0</a></p>
</section>`;
}

const MAIN_FORMATS: [string, string, string?][] = [
  ["latest/ipv4-7d.txt", "text/plain"],
  ["latest/attackers-7d.csv", "text/csv"],
  ["latest/records-7d.ndjson.gz", "application/gzip", "Gzip-compressed NDJSON, one indicator record per line."],
  ["latest/stix/mirage.json", "application/stix+json"],
  ["misp/manifest.json", "application/json"],
];

// Escaped so "</script>" can never close the data block early.
export function datasetLd(feed: FeedIndex | null): string {
  const modified = feed?.generated && ISO.test(feed.generated) && Number.isFinite(Date.parse(feed.generated)) ? feed.generated : undefined;
  const ld = {
    "@context": "https://schema.org",
    "@type": "Dataset",
    name: "Mirage Feed",
    description:
      "Daily threat intelligence from the OffSeq Mirage honeypot fleet: handshake-verified attacker IP addresses seen by several sensors, exploited CVEs, payload and C2 URLs, malware hashes and tool fingerprints.",
    url: `${SITE}/`,
    sameAs: REPO_URL,
    license: "https://creativecommons.org/licenses/by/4.0/",
    isAccessibleForFree: true,
    creator: { "@type": "Organization", name: "OffSeq", url: "https://offseq.com" },
    keywords: ["threat intelligence", "blocklist", "honeypot", "IP reputation", "STIX", "MISP", "CVE", "indicators of compromise"],
    ...(modified ? { dateModified: modified } : {}),
    temporalCoverage: modified ? `${new Date(Date.parse(modified) - 7 * 86_400_000).toISOString().slice(0, 10)}/${modified.slice(0, 10)}` : "P7D",
    distribution: MAIN_FORMATS.map(([path, format, description]) => ({
      "@type": "DataDownload",
      contentUrl: `${BASE}/${path}`,
      encodingFormat: format,
      ...(description ? { description } : {}),
    })),
  };
  return `<script type="application/ld+json">${JSON.stringify(ld).replace(/</g, "\\u003c")}</script>`;
}
