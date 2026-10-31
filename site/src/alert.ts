import type { Env } from "./env";
import { STALE_AFTER_H } from "./home";
import { SITE } from "./html";

// Ahead of the public stale notice.
export const ALERT_AFTER_H = STALE_AFTER_H - 6;
// The cron runs hourly: a new staleness mails within the hour, an ongoing problem repeats at these UTC hours.
const REPEAT_AT = [7, 19];
const FROM = "feeds-alert@platforms.offseq.com";
export const HEALTH_URL = "https://mirage.offseq.com/api/health";

interface Health {
  ok?: boolean;
  degraded?: boolean;
  stale?: unknown[];
  feed?: { day?: string | null; age_s?: number | null };
}

function ageHours(generated: string | undefined, now: number): number | null {
  const built = Date.parse(generated ?? "");
  return Number.isFinite(built) ? Math.floor((now - built) / 3_600_000) : null;
}

export function staleAlert(
  generated: string | undefined,
  health: Health | null,
  now: number,
  repo: string,
): { subject: string; body: string } | null {
  const hours = ageHours(generated, now);
  const stale = hours === null || hours >= ALERT_AFTER_H;
  const backend: string[] = [];
  if (!health) backend.push(`${HEALTH_URL} did not answer`);
  else {
    if (!health.ok || health.degraded) backend.push(`backend health: ok=${health.ok}, degraded=${health.degraded}`);
    if (health.stale?.length) backend.push(`backend stale: ${JSON.stringify(health.stale)}`);
    if ((health.feed?.age_s ?? Infinity) > ALERT_AFTER_H * 3600) backend.push(`newest backend snapshot: ${health.feed?.day ?? "none"}`);
  }
  if (!stale && !backend.length) return null;
  if (hours !== ALERT_AFTER_H && !REPEAT_AT.includes(new Date(now).getUTCHours())) return null;
  const age = hours === null ? "has no readable build time" : `was built ${generated}, ${hours} hours ago`;
  return {
    subject: stale ? `Mirage Feed is stale${hours === null ? "" : ` (${hours} h)`}` : "Mirage Feed backend needs attention",
    body: [
      `The published Mirage Feed ${age}.`,
      ...backend,
      "",
      `Publish runs: https://github.com/${repo}/actions/workflows/publish.yml`,
      `Status: ${SITE}/status.json`,
      `Backend: ${HEALTH_URL}`,
      "",
    ].join("\n"),
  };
}

async function readGenerated(env: Env): Promise<string | undefined> {
  try {
    return ((await (await env.FEED.get("_meta/published.json"))?.json()) as { generated?: string } | null)?.generated;
  } catch (e) {
    console.error("freshness: published.json unreadable", e);
    return undefined;
  }
}

async function readHealth(): Promise<Health | null> {
  try {
    const res = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(15_000), headers: { accept: "application/json" } });
    return res.ok ? ((await res.json()) as Health) : null;
  } catch (e) {
    console.error("freshness: backend health unreadable", e);
    return null;
  }
}

export async function checkFreshness(env: Env, now: number): Promise<void> {
  const alert = staleAlert(await readGenerated(env), await readHealth(), now, env.GITHUB_REPO);
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
    alert.body,
  ].join("\r\n");
  const { EmailMessage } = await import("cloudflare:email");
  await env.ALERT.send(new EmailMessage(FROM, env.ALERT_TO, raw));
}
