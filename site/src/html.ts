import { APP_PATH, FONT_400, FONT_600 } from "./assets";
import { CSS } from "./style";

export const SITE = "https://feeds.offseq.com";
export const BASE = `${SITE}/mirage-feed`;
export const REPO_URL = "https://github.com/offseq/mirage-feed";
export const MIRAGE = "https://mirage.offseq.com";
export const ABUSE = "abuse@offseq.com";

export type Placement = "hero" | "compare" | "ip-lookup" | "status";

// Every call to action opens Mirage's sign-up modal with premium intent; plain informational links stay plain.
export const upsell = (placement: Placement): string =>
  `${MIRAGE}/?auth=signup&intent=premium&utm_source=feeds&utm_medium=web&utm_campaign=mirage-feed&utm_content=${placement}`;

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

export const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d(?:\.\d+)?)?(?:Z|[+-]\d\d:\d\d)$/;

export const utc = (iso: string | undefined): string =>
  iso && /^\d{4}-\d\d-\d\dT\d\d:\d\d/.test(iso) ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : "";

const NAV: [string, string][] = [
  ["status", "status"],
  ["lookup", "lookup"],
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
  noindex?: boolean;
  canonical?: boolean;
  // Belt to the no-referrer header, which a page restored from the back-forward cache may not re-apply.
  noreferrer?: boolean;
}

export function layout(p: Page): string {
  const html = render(p);
  return p.noreferrer ? html.replace(/<a /g, '<a rel="noreferrer" ') : html;
}

function render(p: Page): string {
  const home = p.path === "/";
  const nav = NAV.map(([id, label]) => `<a href="${home ? "" : "/"}#${id}">${label}</a>`).join("");
  const title = `${p.shadow ? "[preview] " : ""}${p.title}`;
  const url = `${SITE}${p.path}`;
  const meta = (attr: string, key: string, value: string) => `<meta ${attr}="${key}" content="${esc(value)}">`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
${meta("name", "description", p.description)}
${p.shadow || p.noindex ? '<meta name="robots" content="noindex,nofollow">\n' : ""}${p.canonical === false ? "" : `<link rel="canonical" href="${esc(url)}">\n`}<meta name="theme-color" content="#f9f7f2" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#101821" media="(prefers-color-scheme: dark)">
${meta("property", "og:type", "website")}
${meta("property", "og:site_name", "OffSeq Mirage")}
${meta("property", "og:title", p.title)}
${meta("property", "og:description", p.description)}
${meta("property", "og:url", url)}
${meta("property", "og:image", `${SITE}/og.png`)}
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
${meta("property", "og:image:alt", "mirage-feed: daily attacker indicators from the OffSeq Mirage honeypot fleet")}
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="alternate" type="application/atom+xml" title="Mirage Feed builds" href="/feed.atom">
<link rel="preload" href="${FONT_400}" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="${FONT_600}" as="font" type="font/woff2" crossorigin>
<style>${CSS}</style>
<script src="${APP_PATH}" defer></script>
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
<p><a href="https://offseq.com">offseq.com</a> &middot; <a href="${MIRAGE}">mirage.offseq.com</a> &middot; <a href="${REPO_URL}">github.com/offseq/mirage-feed</a> &middot; <a href="/privacy">privacy</a> &middot; <a href="/removal">removal</a> &middot; <a href="/.well-known/security.txt">security.txt</a> &middot; <a href="/feed.atom">atom</a></p>
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

export const pre = (code: string, label: string): string =>
  `<pre tabindex="0" aria-label="${esc(label)}"><code>${esc(code)}</code></pre>`;
