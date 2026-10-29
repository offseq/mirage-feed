// Mirrors the offseq-landings collector contract: cookieless Plausible events, never form values or looked-up addresses.
export const ANALYTICS_JS = `const track = (() => {
  const SITE = "https://feeds.offseq.com";
  const ENDPOINT = "https://in.ainalytic.net/api/event";
  const TAG = /^[a-z0-9][a-z0-9._~-]{0,99}$/i;
  const CAMPAIGN = ["utm_source", "utm_medium", "utm_campaign", "utm_content"];

  const allowed = () => {
    if (location.origin !== SITE || navigator.webdriver || /^\\/ip(?:\\/|$)/.test(location.pathname)) return false;
    if (navigator.globalPrivacyControl || ["1", "yes"].includes(navigator.doNotTrack || "")) return false;
    if (/bot|crawler|spider|headless/i.test(navigator.userAgent)) return false;
    const robots = document.querySelector('meta[name="robots"]');
    if (robots && /\\bnoindex\\b/i.test(robots.content)) return false;
    try { if (localStorage.getItem("plausible_ignore") === "true") return false; } catch {}
    return true;
  };

  const pageUrl = () => {
    const canonical = document.querySelector('link[rel="canonical"]');
    if (!canonical) return;
    try {
      const url = new URL(canonical.href);
      if (url.origin !== SITE || url.pathname !== location.pathname) return;
      url.search = "";
      url.hash = "";
      const query = new URLSearchParams(location.search);
      for (const key of CAMPAIGN) {
        const value = query.get(key);
        if (value && TAG.test(value)) url.searchParams.set(key, value);
      }
      return url.href;
    } catch {}
  };

  const referrer = () => {
    try {
      const url = new URL(document.referrer);
      if (url.protocol === "http:" || url.protocol === "https:") return url.origin;
    } catch {}
  };

  const send = (name, props) => {
    if (!allowed()) return;
    const url = pageUrl();
    if (!url) return;
    const body = JSON.stringify({ name, domain: "feeds.offseq.com", url, referrer: referrer(), ...(props ? { props } : {}) });
    try {
      fetch(ENDPOINT, {
        method: "POST", body, keepalive: true, credentials: "omit", referrerPolicy: "no-referrer",
        headers: { "Content-Type": "text/plain" },
      }).catch(() => {});
    } catch {}
  };

  const upsell = (anchor) => {
    try {
      const url = new URL(anchor.href);
      if (url.origin !== "https://mirage.offseq.com" || url.searchParams.get("intent") !== "premium") return;
      const placement = url.searchParams.get("utm_content");
      return { destination: url.hostname + url.pathname, placement: placement && TAG.test(placement) ? placement : "content" };
    } catch {}
  };

  const onClick = (event) => {
    if (!event.isTrusted || event.defaultPrevented || (event.type === "click" ? event.button !== 0 : event.button !== 1)) return;
    const anchor = event.target instanceof Element ? event.target.closest("a[href]") : null;
    const props = anchor && upsell(anchor);
    if (props) send("OffSeq CTA Click", props);
  };

  if (allowed()) {
    document.addEventListener("click", onClick);
    document.addEventListener("onauxclick" in document ? "auxclick" : "mouseup", onClick);
    if (document.prerendering) document.addEventListener("prerenderingchange", () => send("pageview"), { once: true });
    else send("pageview");
    window.addEventListener("pageshow", (event) => { if (event.persisted) send("pageview"); });
  }
  return send;
})();`;

export const APP_JS = `"use strict";
(() => {
${ANALYTICS_JS}

  const live = document.createElement("p");
  live.className = "sr";
  live.setAttribute("role", "status");
  document.body.append(live);

  for (const el of document.querySelectorAll("[data-copy]")) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy";
    btn.textContent = "copy";
    btn.setAttribute("aria-label", "Copy " + (el.dataset.copy || "text"));
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(el.textContent.trim());
        const file = /https:\\/\\/feeds\\.offseq\\.com\\/mirage-feed\\/([A-Za-z0-9._/-]*)/.exec(el.textContent);
        if (file) track("Feed URL Copied", { file: file[1] || "/" });
        btn.dataset.state = "done";
        btn.textContent = "copied";
        live.textContent = "Copied to clipboard";
      } catch {
        btn.dataset.state = "fail";
        btn.textContent = "select";
        live.textContent = "Copy failed, select the text instead";
      }
      setTimeout(() => { delete btn.dataset.state; btn.textContent = "copy"; }, 1600);
    });
    el.after(btn);
  }

  const form = document.querySelector("form[data-removal]");
  if (!form) return;
  const msg = form.querySelector("[data-msg]");
  const submit = form.querySelector("button[type=submit]");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    for (const f of form.querySelectorAll("[aria-invalid]")) {
      f.removeAttribute("aria-invalid");
      f.setAttribute("aria-describedby", f.id + "-hint");
    }
    submit.disabled = true;
    submit.textContent = "Sending";
    try {
      const res = await fetch(form.action, {
        method: "POST",
        headers: { accept: "application/json" },
        body: new URLSearchParams(new FormData(form)),
      });
      if (!(res.headers.get("content-type") || "").includes("application/json")) throw new Error();
      const data = await res.json();
      if (data.ok) {
        track("Removal Submitted");
        const done = document.createElement("div");
        done.className = "msg";
        done.setAttribute("tabindex", "-1");
        done.textContent = data.message;
        form.replaceWith(done);
        done.focus();
        return;
      }
      msg.hidden = false;
      msg.textContent = data.error;
      const field = data.field && form.elements.namedItem(data.field);
      if (field) {
        field.setAttribute("aria-invalid", "true");
        field.setAttribute("aria-describedby", field.id + "-hint form-msg");
        field.focus();
      } else msg.focus();
    } catch {
      msg.hidden = false;
      msg.textContent = "The request could not be sent. Try again, or write to abuse@offseq.com.";
      msg.focus();
    }
    if (window.turnstile) window.turnstile.reset();
    submit.disabled = false;
    submit.textContent = "Send request";
  });
})();
`;
