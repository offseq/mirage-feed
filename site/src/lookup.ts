import { type Addr } from "./addr";
import type { Env } from "./env";
import { getFeedFile, getFeedJson } from "./feed";
import { MIRAGE, esc, num, upsell, utc } from "./html";

export interface IpRecord {
  first_seen?: string;
  last_seen?: string;
  asn?: number | null;
  as_org?: string | null;
  country?: string | null;
  services?: string[];
  tags?: string[];
  attack?: string[];
  cves?: string[];
  kev?: boolean;
  sensors?: number;
  networks?: number;
  hits?: number;
  confidence?: number;
}

export interface Lookup {
  ip: string;
  listed: boolean;
  lists: string[];
  scanner: boolean;
  anonymizer: boolean;
  record: IpRecord | null;
  day: string | null;
  generated: string | null;
}

type Shard = Record<string, { lists?: string[]; record?: IpRecord }>;

const BLOCKLISTS = new Set(["ipv4-1d.txt", "ipv4-7d.txt", "ipv4-30d.txt", "ipv6-7d.txt"]);
const LIST_ORDER = ["ipv4-1d.txt", "ipv4-7d.txt", "ipv4-30d.txt", "ipv6-7d.txt", "anonymizers-7d.txt", "known-scanners-ipv4.txt", "known-scanners-ipv6.txt"];

// The build splits every IP list by first IPv4 octet or first IPv6 hextet, so a lookup reads one small file.
export const shardPath = (addr: Addr) =>
  addr.family === 4 ? `latest/lookup/v4/${addr.value.split(".")[0]}.json` : `latest/lookup/v6/${addr.value.split(":")[0]}.json`;

// null when the shard is unreadable, so an outage is never reported as "Not listed".
async function readShard(addr: Addr, env: Env, origin: string, ctx: ExecutionContext): Promise<Shard | null> {
  const res = await getFeedFile(shardPath(addr), env, origin, ctx);
  if (res.status === 404) return {};
  if (!res.ok) return null;
  try {
    return (await res.json()) as Shard;
  } catch {
    return null;
  }
}

export async function lookup(addr: Addr, env: Env, origin: string, ctx: ExecutionContext): Promise<Lookup | null> {
  const [shard, feed] = await Promise.all([
    readShard(addr, env, origin, ctx),
    getFeedJson<{ day?: string; generated?: string; files?: { path?: string }[] }>("feed.json", env, origin, ctx),
  ]);
  // A build without the shard index can't tell absent from unknown.
  if (!shard || !feed?.files?.some((f) => f.path === "latest/lookup/")) return null;
  const entry = Object.hasOwn(shard, addr.value) ? shard[addr.value] : undefined;
  // The top lists are subsets of ipv4-7d.txt; the page names the windows only.
  const lists = LIST_ORDER.filter((l) => entry?.lists?.includes(l));
  return {
    ip: addr.value,
    listed: lists.some((l) => BLOCKLISTS.has(l)),
    lists,
    scanner: lists.some((l) => l.startsWith("known-scanners-")),
    anonymizer: lists.includes("anonymizers-7d.txt"),
    record: entry?.record ?? null,
    day: feed.day ?? null,
    generated: feed.generated ?? null,
  };
}

const attackUrl = (t: string) => `https://attack.mitre.org/techniques/${t.replace(".", "/")}/`;
const joined = (items: string[] | undefined, render: (s: string) => string = esc) =>
  items?.length ? items.map(render).join(", ") : '<span class="dim">-</span>';

export function lookupForm(value = "", error = ""): string {
  return `<form class="lookup" method="get" action="/ip" role="search" aria-label="Look up an address">
${error ? `<p class="msg err" id="lookup-msg" role="alert">${esc(error)}</p>\n` : ""}<label for="addr">IPv4 address, or IPv6 address or /64</label>
<div class="row"><input id="addr" name="addr" required maxlength="64" autocomplete="off" spellcheck="false" inputmode="text" value="${esc(value)}"${error ? ' aria-invalid="true" aria-describedby="lookup-msg"' : ""}><button type="submit">Look up</button></div>
</form>`;
}

const RECENT = new Set(["ipv4-1d.txt", "ipv4-7d.txt", "ipv6-7d.txt"]);

function verdict(l: Lookup): string {
  if (l.scanner) return "Known research scanner. It is excluded from the blocklists and published in the known-scanners list so you can allowlist it.";
  if (l.anonymizer && !l.listed) return "VPN or Tor exit seen attacking. It is kept out of the blocklists because many people share it, and listed in anonymizers-7d.txt for enrichment.";
  if (l.listed && !l.lists.some((p) => RECENT.has(p))) return "Listed in ipv4-30d.txt only. It was seen attacking in the last 30 days, not in the 7-day lists.";
  if (l.listed) return "Listed. Mirage sensors in several networks saw this address attacking in the last 7 days.";
  return "Not listed. This address is in none of the current lists.";
}

export function renderLookup(l: Lookup): string {
  const r = l.record;
  const network = r?.asn ? `AS${esc(r.asn)}${r.as_org ? ` ${esc(r.as_org)}` : ""}${r.country ? ` <span class="dim">${esc(r.country)}</span>` : ""}` : null;
  const rows: [string, string][] = [["Lists", joined(l.lists, (p) => `<a href="/mirage-feed/latest/${esc(p)}">${esc(p)}</a>`)]];
  if (r) {
    rows.push(
      ["First seen", esc(utc(r.first_seen)) || "-"],
      ["Last seen", esc(utc(r.last_seen)) || "-"],
      ["Network", network ?? '<span class="dim">-</span>'],
      ["Seen by", `${num(r.sensors)} sensors in ${num(r.networks)} networks, ${num(r.hits)} hits`],
      ["Services", joined(r.services)],
      ["Tags", joined(r.tags)],
      ["ATT&amp;CK", joined(r.attack, (t) => `<a href="${attackUrl(esc(t))}">${esc(t)}</a>`)],
      ["CVEs", joined(r.cves, (c) => `<a href="${MIRAGE}/cve/${esc(c)}">${esc(c)}</a>`)],
      ["Confidence", r.confidence === undefined ? "-" : `${num(r.confidence)} / 100`],
    );
  }
  const table = rows.map(([k, v]) => `<tr><th scope="row">${k}</th><td>${v}</td></tr>`).join("");
  const build = l.day ? `<p class="dim">Build of ${esc(l.day)}${l.generated ? `, ${esc(utc(l.generated))}` : ""}. <a href="/ip/${esc(l.ip.replace(/\/64$/, ""))}.json">JSON</a></p>` : "";
  const removal = l.listed || l.anonymizer || r
    ? `<p>Hold this address and think the listing is wrong? <a href="/removal?ip=${encodeURIComponent(l.ip)}">Request removal</a>.</p>`
    : "";
  return `<section aria-labelledby="h-ip"><h1 id="h-ip">Address <code class="addr">${esc(l.ip)}</code></h1>
<p class="msg${l.listed ? " err" : ""}">${esc(verdict(l))}</p>
<div class="scroll" tabindex="0" role="region" aria-label="Details for ${esc(l.ip)}"><table><tbody>${table}</tbody></table></div>
${build}
${removal}
<p>Session timelines, payloads and every source, including single-sensor activity: <a href="${esc(upsell("ip-lookup"))}">full context in OffSeq Mirage</a>.</p>
</section>
<section aria-labelledby="h-again"><h2 id="h-again">Look up another address</h2>
${lookupForm()}
</section>`;
}
