import type { Env } from "./env";
import { getFeedFile, getFeedJson } from "./feed";
import { MIRAGE, esc, num, upsell, utc } from "./html";
import { V4, publicV4, publicV6 } from "./removal";

export interface Addr {
  family: 4 | 6;
  // As written in the feed files: a bare IPv4 address or an IPv6 /64.
  value: string;
  // The canonical /ip/<slug> path segment.
  slug: string;
}

function expandV6(host: string): string[] {
  const [head, tail] = host.split("::");
  const left = head ? head.split(":") : [];
  const right = tail === undefined ? [] : tail ? tail.split(":") : [];
  return [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
}

export function parseAddr(raw: string): Addr | null {
  const input = raw.trim();
  if (!input || input.length > 64 || !/^[0-9A-Fa-f:./]+$/.test(input)) return null;
  const [addr, prefix, ...rest] = input.split("/");
  if (rest.length) return null;
  if (V4.test(addr)) return prefix === undefined && publicV4(addr) ? { family: 4, value: addr, slug: addr } : null;
  if ((prefix !== undefined && prefix !== "64") || !addr.includes(":") || addr.includes(".")) return null;
  let host: string;
  try {
    host = new URL(`http://[${addr}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
  const net = new URL(`http://[${[...expandV6(host).slice(0, 4), "0", "0", "0", "0"].join(":")}]/`).hostname.slice(1, -1);
  return publicV6(net) ? { family: 6, value: `${net}/64`, slug: net } : null;
}

export interface IpRecord {
  value: string;
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

const RECORDS = "latest/records-7d.ndjson.gz";
const ANONYMIZERS = "latest/anonymizers-7d.txt";
const SCANNERS = { 4: "latest/known-scanners-ipv4.txt", 6: "latest/known-scanners-ipv6.txt" };
const BLOCKLISTS = { 4: ["latest/ipv4-1d.txt", "latest/ipv4-7d.txt", "latest/ipv4-30d.txt"], 6: ["latest/ipv6-7d.txt"] };

// One parse per path, kept only for the current object version; sharing the promise lets concurrent cold
// lookups wait on a single parse.
const memo = new Map<string, { etag: string; data: Promise<unknown> }>();

async function indexed<T>(path: string, env: Env, origin: string, ctx: ExecutionContext, parse: (res: Response) => Promise<T>): Promise<T | null> {
  const res = await getFeedFile(path, env, origin, ctx);
  if (!res.ok) return null;
  const etag = res.headers.get("etag") ?? "";
  let hit = memo.get(path);
  if (hit && hit.etag === etag) {
    await res.body?.cancel();
  } else {
    hit = { etag, data: parse(res) };
    memo.set(path, hit);
  }
  try {
    return (await hit.data) as T;
  } catch {
    if (memo.get(path) === hit) memo.delete(path);
    return null;
  }
}

const lineSet = async (res: Response) => new Set((await res.text()).split("\n").map((l) => l.trim()).filter(Boolean));

async function recordMap(res: Response): Promise<Map<string, IpRecord>> {
  const text = await new Response(res.body!.pipeThrough(new DecompressionStream("gzip"))).text();
  const map = new Map<string, IpRecord>();
  for (const line of text.split("\n")) {
    if (!line) continue;
    try {
      const r = JSON.parse(line) as IpRecord & { type?: string };
      if (r.type === "ipv4" || r.type === "ipv6") map.set(r.value, r);
    } catch {
      continue;
    }
  }
  return map;
}

export async function lookup(addr: Addr, env: Env, origin: string, ctx: ExecutionContext): Promise<Lookup | null> {
  const set = (path: string) => indexed(path, env, origin, ctx, lineSet);
  const lists = [...BLOCKLISTS[addr.family], ANONYMIZERS, SCANNERS[addr.family]];
  const [records, feed, ...sets] = await Promise.all([
    indexed(RECORDS, env, origin, ctx, recordMap),
    getFeedJson<{ day?: string; generated?: string }>("feed.json", env, origin, ctx),
    ...lists.map(set),
  ]);
  if (!records) return null;
  const matches = (s: Set<string> | null) => !!s && (s.has(addr.value) || s.has(addr.slug));
  const found = lists.filter((_, i) => matches(sets[i])).map((p) => p.slice("latest/".length));
  return {
    ip: addr.value,
    listed: found.some((p) => BLOCKLISTS[addr.family].includes(`latest/${p}`)),
    lists: found,
    scanner: found.includes(SCANNERS[addr.family].slice("latest/".length)),
    anonymizer: found.includes(ANONYMIZERS.slice("latest/".length)),
    record: records.get(addr.value) ?? null,
    day: feed?.day ?? null,
    generated: feed?.generated ?? null,
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
