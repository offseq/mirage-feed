import { ABUSE, REPO_URL, esc } from "./html";
import { REASON_MAX, REASON_MIN } from "./removal";

export interface RemovalForm {
  ip?: string;
  email?: string;
  reason?: string;
  error?: string;
  field?: string;
}

const described = (f: RemovalForm, name: string) =>
  f.field === name ? ` aria-invalid="true" aria-describedby="${name}-hint form-msg"` : ` aria-describedby="${name}-hint"`;

export function renderRemoval(f: RemovalForm, sitekey: string): string {
  return `<section aria-labelledby="h-removal"><h1 id="h-removal">Removal request</h1>
<p>Ask for an address to be taken out of the Mirage Feed. No account needed. Requests are handled within 72 hours and you get a reply at the email you give. An address that resumes attacking is listed again.</p>
<p>Prefer email? Write to <a href="mailto:${ABUSE}">${ABUSE}</a>.</p>
<form method="post" action="/removal" data-removal>
<p class="msg err" id="form-msg" role="alert" tabindex="-1" data-msg${f.error ? " autofocus" : " hidden"}>${esc(f.error ?? "")}</p>
<label for="ip">IP address</label>
<span class="hint" id="ip-hint">One public IPv4 address, or IPv6 address or /64 as listed.</span>
<input id="ip" name="ip" required maxlength="64" autocomplete="off" spellcheck="false" inputmode="text" value="${esc(f.ip)}"${described(f, "ip")}>
<label for="email">Email</label>
<span class="hint" id="email-hint">For our reply.</span>
<input id="email" name="email" type="email" required maxlength="254" autocomplete="email" value="${esc(f.email)}"${described(f, "email")}>
<label for="reason">Reason</label>
<span class="hint" id="reason-hint">${REASON_MIN} to ${REASON_MAX.toLocaleString("en-US")} characters, e.g. who holds the address and why it is not hostile.</span>
<textarea id="reason" name="reason" required minlength="${REASON_MIN}" maxlength="${REASON_MAX}"${described(f, "reason")}>${esc(f.reason)}</textarea>
<div class="hp" aria-hidden="true"><label for="website">Website</label><input id="website" name="website" tabindex="-1" autocomplete="off"></div>
<div class="cf-turnstile" data-sitekey="${esc(sitekey)}" data-action="removal"></div>
<noscript><p class="msg err">The anti-abuse check on this form needs JavaScript. Without it, send the same details to <a href="mailto:${ABUSE}">${ABUSE}</a>.</p></noscript>
<button type="submit">Send request</button>
</form>
<p class="dim">We use these details only to handle this request. See the <a href="/privacy">privacy notice</a>.</p>
</section>`;
}

export const REMOVAL_SENT =
  "Request received. You will hear from abuse@offseq.com within 72 hours. Listed addresses also drop out on their own 7 days after the last observed activity.";

export function renderRemovalSent(): string {
  return `<section aria-labelledby="h-sent"><h1 id="h-sent">Request received</h1>
<p>${esc(REMOVAL_SENT)}</p>
<p><a href="/">Back to the feed</a></p>
</section>`;
}

export const PRIVACY_UPDATED = "2026-10-24";

export function renderPrivacy(): string {
  return `<section aria-labelledby="h-privacy"><h1 id="h-privacy">Privacy notice</h1>
<p class="dim">Mirage Feed and feeds.offseq.com. Last updated ${PRIVACY_UPDATED}.</p>
</section>

<section aria-labelledby="h-controller"><h2 id="h-controller">Controller</h2>
<p>SEQ SIA, registration no. 40203410806, Lastādijas iela 12 k-3, Riga, LV-1050, Latvia, trading as OffSeq. Contact for data protection matters: <a href="mailto:support@offseq.com">support@offseq.com</a>. Listing and removal requests: <a href="mailto:${ABUSE}">${ABUSE}</a>.</p>
</section>

<section aria-labelledby="h-what"><h2 id="h-what">What the feed publishes</h2>
<ul>
<li>Attacker IP addresses (IPv6 as /64 prefixes) with their network (ASN and its registered name), country, first and last sighting truncated to the hour, and tags.</li>
<li>Payload and command-and-control URLs, domains, and SHA-256 hashes of delivered files.</li>
<li>Tool fingerprints (HASSH and JA4H).</li>
<li>The most common attacker user agents and request paths.</li>
<li>The 100 most attempted passwords, without usernames.</li>
<li>Aggregate statistics: counts by network, country, service and ATT&amp;CK technique.</li>
</ul>
<p>An IP address can be personal data when it can be linked to a person, so we treat every listed address as personal data. The feed does not publish usernames, session contents or captured credential pairs.</p>
</section>

<section aria-labelledby="h-basis"><h2 id="h-basis">Purpose and legal basis</h2>
<p>The purpose is network and information security: helping operators block addresses that are actively attacking systems. The legal basis is our legitimate interest and that of the feed's users under Article 6(1)(f) GDPR. Recital 49 names ensuring network and information security, including stopping attacks and damage to systems, as a legitimate interest.</p>
<p>To keep the impact on address holders low, an address is listed only after a completed TCP handshake, seen by several sensors in different networks, at least 24 hours after first sighting, and it drops out 7 days after its last activity. See <a href="/#methodology">how an IP gets listed</a>.</p>
</section>

<section aria-labelledby="h-retention"><h2 id="h-retention">Retention</h2>
<p>Lists are rebuilt every day. An address leaves the 1-day and 7-day lists 7 days after its last observed activity, and the 30-day list 30 days after it.</p>
<p>The published data branch is force-pushed on every build, so its git history is not kept. Two places hold older data: the MISP feed carries up to 7 previous daily events, and weekly release archives keep statistics and indicators other than IP addresses. Copies already downloaded by third parties are outside our control.</p>
</section>

<section aria-labelledby="h-recipients"><h2 id="h-recipients">Recipients</h2>
<p>The feed is public under CC BY 4.0, so anyone can receive it. It is stored on GitHub (<a href="${REPO_URL}">offseq/mirage-feed</a>) and served through Cloudflare. GitHub and Cloudflare are US companies; transfers to them rely on the European Commission adequacy decision for the EU-US Data Privacy Framework, with Standard Contractual Clauses as the fallback.</p>
</section>

<section aria-labelledby="h-site"><h2 id="h-site">This website</h2>
<p>No cookies and no third-party fonts. The removal form alone loads Cloudflare Turnstile to block automated submissions. When a feed file is downloaded we count the download in aggregate: file path, network (ASN), country and client type such as curl or a firewall product. The IP address and full user agent are not stored. Cloudflare processes requests as our hosting provider.</p>
<p>We measure use of the pages with two cookieless tools. Cloudflare Web Analytics, added by Cloudflare to our pages, reports aggregate page views and load times. Our self-hosted Plausible at in.ainalytic.net receives the page address without its query string (only <code>utm_</code> campaign tags are kept), the origin of the referring site, and these events: a page view, <code>OffSeq CTA Click</code> with the link destination and its placement, <code>Feed URL Copied</code> with the file path, and <code>Removal Submitted</code> with no details. Plausible stores no personal data and no IP address. Nothing is sent when your browser signals Global Privacy Control or Do Not Track.</p>
<p>The address lookup at <code>/ip</code> answers from the published lists only. Lookup pages send nothing to either analytics tool, and what you type into the lookup or the removal form is never sent to them. The addresses you look up are not logged; we keep only aggregate counts of lookups and whether the result was listed. Lookups are rate-limited per client address, which is held in memory for at most a minute and not stored.</p>
<p><code>/status.json</code> and the badges under <code>/badge/</code> publish build freshness and list sizes only, no personal data.</p>
</section>

<section aria-labelledby="h-requests"><h2 id="h-requests">Removal requests</h2>
<p>The removal form collects the IP address to remove, your email and a reason, and passes on the IP address you send the form from so we can limit abuse. We use them only to handle the request and reply, and keep them for 12 months after the request is closed.</p>
</section>

<section aria-labelledby="h-rights"><h2 id="h-rights">Your rights</h2>
<p>You can ask for access to, rectification or erasure of data about you, restriction of processing, and you can object to processing based on legitimate interest under Article 21 GDPR. The quickest route for a listed address is the <a href="/removal">removal form</a>.</p>
<p>You can complain to the Latvian supervisory authority, Datu valsts inspekcija, at <a href="https://www.dvi.gov.lv">dvi.gov.lv</a>, or to the authority where you live or work.</p>
</section>`;
}

export function renderNotFound(path: string): string {
  return `<section aria-labelledby="h-404"><h1 id="h-404">Not found</h1>
<p>Nothing at <code>${esc(path)}</code>.</p>
<pre><code><a href="/">/</a>                         index, status and files
<a href="/removal">/removal</a>                  removal request
<a href="/privacy">/privacy</a>                  privacy notice
<a href="/mirage-feed/feed.json">/mirage-feed/feed.json</a>    file index</code></pre>
</section>`;
}
