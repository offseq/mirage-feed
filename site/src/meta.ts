import { MINISIGN_PUBKEY } from "./home";
import { ISO, SITE, esc, num } from "./html";

export interface HistoryRow {
  day?: string;
  generated?: string;
  ips_7d?: number;
  active_24h?: number;
  added?: number;
  removed?: number;
  cves?: number;
  urls?: number;
  hashes?: number;
  scanners?: number;
  anonymizers?: number;
}

export function renderAtom(history: HistoryRow[] | null, now: number): string {
  const rows = (Array.isArray(history) ? history : [])
    .filter((r) => /^\d{4}-\d\d-\d\d$/.test(r?.day ?? "") && ISO.test(r?.generated ?? ""))
    .sort((a, b) => b.day!.localeCompare(a.day!));
  const updated = rows[0]?.generated ?? new Date(now).toISOString();
  const entries = rows
    .map((r) => {
      const summary = [
        `${num(r.ips_7d)} IPs in the 7-day list (${num(r.added)} added, ${num(r.removed)} removed)`,
        `${num(r.active_24h)} active in the last 24 hours`,
        `${num(r.cves)} CVEs`,
        `${num(r.urls)} payload URLs`,
        `${num(r.hashes)} malware hashes`,
        `${num(r.scanners)} research scanners excluded`,
        `${num(r.anonymizers)} anonymizers`,
      ].join(", ");
      return `<entry>
<id>tag:feeds.offseq.com,2026:build/${esc(r.day)}</id>
<title>Mirage Feed build ${esc(r.day)}</title>
<updated>${esc(r.generated)}</updated>
<link rel="alternate" type="text/html" href="${SITE}/"/>
<summary>${esc(summary)}.</summary>
</entry>`;
    })
    .join("\n");
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<id>tag:feeds.offseq.com,2026:mirage-feed</id>
<title>Mirage Feed builds</title>
<subtitle>One entry per daily build of the OffSeq Mirage community feed.</subtitle>
<updated>${esc(updated)}</updated>
<author><name>OffSeq</name><uri>https://offseq.com</uri></author>
<link rel="self" type="application/atom+xml" href="${SITE}/feed.atom"/>
<link rel="alternate" type="text/html" href="${SITE}/"/>
<rights>CC BY 4.0</rights>
${entries}
</feed>
`;
}

export function securityTxt(now: number): string {
  const expires = new Date(now);
  expires.setUTCMonth(expires.getUTCMonth() + 11);
  expires.setUTCHours(0, 0, 0, 0);
  return `Contact: https://cvd.cert.lv/programs/view/101
Contact: mailto:security@offseq.com
Expires: ${expires.toISOString()}
Policy: https://cvd.cert.lv/programs/view/101
Preferred-Languages: en, lv
Canonical: ${SITE}/.well-known/security.txt
`;
}

// minisign stores the key id little-endian after the two-byte "Ed" algorithm tag; the comment shows it as hex.
const keyId = [...Uint8Array.from(atob(MINISIGN_PUBKEY), (c) => c.charCodeAt(0)).slice(2, 10)]
  .reverse()
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("")
  .toUpperCase();
export const MINISIGN_PUB = `untrusted comment: minisign public key ${keyId}\n${MINISIGN_PUBKEY}\n`;
