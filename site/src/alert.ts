import type { Env } from "./env";
import { STALE_AFTER_H } from "./home";
import { SITE } from "./html";

// Ahead of the public stale notice.
export const ALERT_AFTER_H = STALE_AFTER_H - 6;
// The cron runs hourly: a new staleness mails within the hour, an ongoing problem repeats at these UTC hours.
const REPEAT_AT = [7, 19];
// A failing tick is retried every 10 min and a refused day every 2 h, so these mail at once when reached.
const FAILING_H = 1;
const REFUSED_H = 6;
const FROM = "feeds-alert@platforms.offseq.com";
export const HEALTH_URL = "https://mirage.offseq.com/api/health";

export interface Health {
  ok?: boolean;
  degraded?: boolean;
  stale?: unknown[];
  feed?: {
    day?: string | null;
    age_s?: number | null;
    refused?: { day?: string; why?: string; since?: number } | null;
    failing?: { error?: string; since?: number } | null;
  };
}

export interface Published {
  generated?: string;
  day?: string;
}

// problem triggers a mail; lastRun only explains one.
export interface DispatchReport {
  problem?: string;
  lastRun?: string;
}

const hoursSince = (ms: number, now: number): number | null => (Number.isFinite(ms) ? Math.floor((now - ms) / 3_600_000) : null);

export function staleAlert(
  published: Published | null,
  health: Health | null,
  now: number,
  repo: string,
  dispatch: DispatchReport = {},
): { subject: string; body: string } | null {
  const generated = published?.generated;
  const hours = hoursSince(Date.parse(generated ?? ""), now);
  const stale = hours === null || hours >= ALERT_AFTER_H;
  const feed = health?.feed;
  const refusedH = hoursSince((feed?.refused?.since ?? NaN) * 1000, now);
  const failingH = hoursSince((feed?.failing?.since ?? NaN) * 1000, now);
  const problems: string[] = [];
  if (!health) problems.push(`${HEALTH_URL} did not answer`);
  else {
    if (!health.ok || health.degraded) problems.push(`backend health: ok=${health.ok}, degraded=${health.degraded}`);
    if (health.stale?.length) problems.push(`backend stale: ${JSON.stringify(health.stale)}`);
    if ((feed?.age_s ?? Infinity) > ALERT_AFTER_H * 3600) problems.push(`newest backend snapshot: ${feed?.day ?? "none"}`);
  }
  if (dispatch.problem) problems.push(dispatch.problem);
  if (!stale && !problems.length) return null;
  const onset = hours === ALERT_AFTER_H || refusedH === REFUSED_H || failingH === FAILING_H;
  if (!onset && !REPEAT_AT.includes(new Date(now).getUTCHours())) return null;
  const causes: string[] = [];
  if (feed?.refused) causes.push(`backend refused the ${feed.refused.day} build (${refusedH ?? "?"} h): ${feed.refused.why}`);
  if (feed?.failing) causes.push(`backend feed tick failing (${failingH ?? "?"} h): ${feed.failing.error}`);
  if (stale && feed?.day && published?.day)
    causes.push(
      feed.day > published.day
        ? `backend day ${feed.day} is built but not published (published ${published.day}): check the publish runs`
        : `backend has built nothing newer than the published ${published.day}`,
    );
  if (dispatch.lastRun) causes.push(dispatch.lastRun);
  const age = hours === null ? "has no readable build time" : `was built ${generated}, ${hours} hours ago`;
  return {
    subject: stale ? `Mirage Feed is stale${hours === null ? "" : ` (${hours} h)`}` : "Mirage Feed needs attention",
    body: [
      `The published Mirage Feed ${age}.`,
      ...problems,
      ...causes,
      "",
      `Publish runs: https://github.com/${repo}/actions/workflows/publish.yml`,
      `Status: ${SITE}/status.json`,
      `Backend: ${HEALTH_URL}`,
      "",
    ].join("\n"),
  };
}

export async function readPublished(env: Env): Promise<Published | null> {
  try {
    return (await (await env.FEED.get("_meta/published.json"))?.json()) ?? null;
  } catch (e) {
    console.error("cron: published.json unreadable", e);
    return null;
  }
}

export async function readHealth(): Promise<Health | null> {
  try {
    const res = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(15_000), headers: { accept: "application/json" } });
    return res.ok ? ((await res.json()) as Health) : null;
  } catch (e) {
    console.error("cron: backend health unreadable", e);
    return null;
  }
}

export async function checkFreshness(env: Env, now: number, dispatch: DispatchReport = {}): Promise<void> {
  const alert = staleAlert(await readPublished(env), await readHealth(), now, env.GITHUB_REPO, dispatch);
  if (!alert) return;
  // Observability is off, so console output in `wrangler tail` is the only trace of a missed alert.
  if (!env.ALERT) {
    console.error(`freshness: no ALERT binding; ${alert.subject}`);
    return;
  }
  const raw = [
    `From: Mirage Feed <${FROM}>`,
    `To: ${env.ALERT_TO}`,
    `Subject: ${alert.subject}`,
    `Date: ${new Date(now).toUTCString()}`,
    `Message-ID: <${crypto.randomUUID()}@platforms.offseq.com>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    ...alert.body.split("\n"),
  ].join("\r\n");
  const { EmailMessage } = await import("cloudflare:email");
  await env.ALERT.send(new EmailMessage(FROM, env.ALERT_TO, raw));
}
