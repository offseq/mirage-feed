import { CSS } from "./style";

export const SITE = "https://feeds.offseq.com";
export const BASE = `${SITE}/mirage-feed`;
export const REPO_URL = "https://github.com/offseq/mirage-feed";
export const CTA_URL = "https://mirage.offseq.com/?utm_source=feeds&utm_medium=web&utm_campaign=mirage-feed";
export const ABUSE = "abuse@offseq.com";

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const esc = (v: unknown): string => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);

export const num = (n: number | undefined): string =>
  typeof n === "number" && Number.isFinite(n) ? n.toLocaleString("en-US") : "-";

export function bytes(n: number | undefined): string {
  if (typeof n !== "number" || !Number.isFinite(n)) return "-";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

export const utc = (iso: string | undefined): string =>
  iso && /^\d{4}-\d\d-\d\dT\d\d:\d\d/.test(iso) ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : "";

const NAV: [string, string][] = [
  ["status", "status"],
  ["subscribe", "subscribe"],
  ["files", "files"],
  ["integrate", "integrate"],
  ["methodology", "listing"],
  ["full-feed", "full feed"],
  ["verify", "verify"],
];

export interface Page {
  title: string;
  description: string;
  path: string;
  body: string;
  shadow: boolean;
  day?: string;
  head?: string;
}

export function layout(p: Page): string {
  const home = p.path === "/";
  const nav = NAV.map(([id, label]) => `<a href="${home ? "" : "/"}#${id}">${label}</a>`).join("");
  const title = `${p.shadow ? "[preview] " : ""}${p.title}`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(p.description)}">
${p.shadow ? '<meta name="robots" content="noindex,nofollow">\n' : ""}<link rel="canonical" href="${SITE}${p.path}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="preload" href="/fonts/plex-mono-400.woff2" as="font" type="font/woff2" crossorigin>
<style>${CSS}</style>
<script src="/app.js" defer></script>
${p.head ? `${p.head}\n` : ""}</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<div class="sheet">
<header>
<div class="run"><a href="/"><b>MIRAGE-FEED(7)</b></a><span><span class="tlp">TLP:CLEAR</span>${p.shadow ? '<span class="preview" title="Private preview, not yet public">preview</span>' : ""}</span><span>OffSeq Mirage</span></div>
<nav class="toc" aria-label="Sections">${nav}<a href="/removal">removal</a><a href="/privacy">privacy</a></nav>
</header>
<main id="main">
${p.body}
</main>
<footer>
<p>Data <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>, credit &quot;OffSeq Mirage&quot; with a link to this site. Marked TLP:CLEAR. Provided as is, without warranty. You decide what to block.</p>
<p><a href="https://offseq.com">offseq.com</a> &middot; <a href="https://mirage.offseq.com">mirage.offseq.com</a> &middot; <a href="${REPO_URL}">github.com/offseq/mirage-feed</a> &middot; <a href="/privacy">privacy</a> &middot; <a href="/removal">removal</a> &middot; <a href="/.well-known/security.txt">security.txt</a></p>
<div class="run"><span>OffSeq</span><span>${esc(p.day ?? "")}</span><span>MIRAGE-FEED(7)</span></div>
</footer>
</div>
</body>
</html>
`;
}

export const copyable = (text: string, label: string): string =>
  `<code class="sel" data-copy="${esc(label)}">${esc(text)}</code>`;

export const cmd = (text: string, label: string): string =>
  `<div class="cmd"><span class="p" aria-hidden="true">$</span>${copyable(text, label)}</div>`;
