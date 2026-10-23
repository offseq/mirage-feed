import { describe, expect, it, vi } from "vitest";
import { ANALYTICS_JS } from "../src/app";

class FakeElement {
  constructor(readonly href = "") {}
  closest(selector: string) {
    return selector === "a[href]" && this.href ? this : null;
  }
}

interface Env {
  path?: string;
  search?: string;
  canonical?: string | null;
  robots?: string;
  navigator?: Record<string, unknown>;
  ignore?: string;
}

function run(o: Env = {}) {
  const path = o.path ?? "/";
  const fetch = vi.fn(async () => new Response(null, { status: 202 }));
  const listeners: Record<string, (e: unknown) => void> = {};
  const canonical = o.canonical === undefined ? `https://feeds.offseq.com${path}` : o.canonical;
  const document = {
    referrer: "https://www.google.com/search?q=mirage+feed",
    onauxclick: null,
    querySelector: (sel: string) =>
      sel === 'link[rel="canonical"]' ? (canonical ? { href: canonical } : null) : sel === 'meta[name="robots"]' && o.robots ? { content: o.robots } : null,
    addEventListener: (type: string, fn: (e: unknown) => void) => (listeners[type] = fn),
  };
  const globals = {
    location: { origin: "https://feeds.offseq.com", pathname: path, search: o.search ?? "" },
    navigator: { userAgent: "Mozilla/5.0 Firefox/131.0", doNotTrack: null, webdriver: false, ...o.navigator },
    localStorage: { getItem: () => o.ignore ?? null },
    window: { addEventListener: () => {} },
    document,
    fetch,
    Element: FakeElement,
  };
  const track = new Function(...Object.keys(globals), `${ANALYTICS_JS}\nreturn track;`)(...Object.values(globals)) as (name: string, props?: Record<string, string>) => void;
  const sent = () => fetch.mock.calls.map((c) => JSON.parse((c as unknown as [string, RequestInit])[1].body as string));
  return { fetch, listeners, track, sent };
}

describe("analytics", () => {
  it("sends a pageview with the canonical URL, utm tags only and the referrer origin", () => {
    const { fetch, sent } = run({ search: "?utm_source=reddit&utm_content=<x>&ip=9.9.9.9&q=secret" });
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://in.ainalytic.net/api/event");
    expect(init).toMatchObject({ method: "POST", keepalive: true, credentials: "omit", referrerPolicy: "no-referrer", headers: { "Content-Type": "text/plain" } });
    expect(sent()).toEqual([{ name: "pageview", domain: "feeds.offseq.com", url: "https://feeds.offseq.com/?utm_source=reddit", referrer: "https://www.google.com" }]);
  });

  it.each<[string, Env]>([
    ["lookup pages", { path: "/ip/9.9.9.9", canonical: "https://feeds.offseq.com/ip/9.9.9.9" }],
    ["the lookup form page", { path: "/ip" }],
    ["Global Privacy Control", { navigator: { globalPrivacyControl: true } }],
    ["Do Not Track", { navigator: { doNotTrack: "1" } }],
    ["automation", { navigator: { webdriver: true } }],
    ["bots", { navigator: { userAgent: "Googlebot/2.1" } }],
    ["noindex pages", { robots: "noindex,nofollow" }],
    ["plausible_ignore", { ignore: "true" }],
    ["pages without a canonical URL", { canonical: null }],
  ])("sends nothing for %s, even when an event fires", (_, env) => {
    const { fetch, track, listeners } = run(env);
    track("Feed URL Copied", { file: "latest/ipv4-7d.txt" });
    listeners.click?.({ isTrusted: true, type: "click", button: 0, target: new FakeElement("https://mirage.offseq.com/?intent=premium") });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("tracks upsell clicks with destination and placement, and ignores other links", () => {
    const { listeners, sent } = run();
    const click = (href: string, extra = {}) => listeners.click({ isTrusted: true, type: "click", button: 0, target: new FakeElement(href), ...extra });
    click("https://mirage.offseq.com/?auth=signup&intent=premium&utm_content=compare");
    click("https://mirage.offseq.com/cve/CVE-2024-3400");
    click("https://mirage.offseq.com/?auth=signup&intent=premium&utm_content=hero", { isTrusted: false });
    expect(sent().slice(1)).toEqual([
      { name: "OffSeq CTA Click", domain: "feeds.offseq.com", url: "https://feeds.offseq.com/", referrer: "https://www.google.com", props: { destination: "mirage.offseq.com/", placement: "compare" } },
    ]);
  });

  it("is wired into app.js for copies and removals, without reading field values", async () => {
    const { APP_JS } = await import("../src/app");
    expect(APP_JS).toContain('track("Feed URL Copied", { file: file[1] || "/" })');
    expect(APP_JS).toContain('track("Removal Submitted");');
    expect(ANALYTICS_JS).not.toMatch(/\.value\b|FormData|elements/);
    const re = new Function(`return ${/(\/https:.*?\/)\.exec\(el\.textContent\)/.exec(APP_JS)![1]};`)() as RegExp;
    expect(re.exec("curl -fsSL https://feeds.offseq.com/mirage-feed/latest/ipv4-7d.txt")![1]).toBe("latest/ipv4-7d.txt");
    expect(re.exec("https://feeds.offseq.com/mirage-feed/misp/")![1]).toBe("misp/");
  });
});
