import type { Env } from "./env";
import { STALE_AFTER_H } from "./home";
import { SITE } from "./html";

// Ahead of the public stale notice; the cron runs twice a day, so a stale feed mails at most twice daily.
export const ALERT_AFTER_H = STALE_AFTER_H - 6;
const FROM = "feeds-alert@platforms.offseq.com";

export function staleAlert(generated: string | undefined, now: number, repo: string): { subject: string; body: string } | null {
  const built = Date.parse(generated ?? "");
  const hours = Number.isFinite(built) ? Math.floor((now - built) / 3_600_000) : null;
  if (hours !== null && hours < ALERT_AFTER_H) return null;
  const age = hours === null ? "has no readable build time" : `was built ${generated}, ${hours} hours ago`;
  return {
    subject: `Mirage Feed is stale${hours === null ? "" : ` (${hours} h)`}`,
    body: `The published Mirage Feed ${age}.\n\nPublish runs: https://github.com/${repo}/actions/workflows/publish.yml\nStatus: ${SITE}/status.json\n`,
  };
}

export async function checkFreshness(env: Env, now: number): Promise<void> {
  if (!env.ALERT) return;
  const meta = (await (await env.FEED.get("_meta/published.json"))?.json().catch(() => null)) as { generated?: string } | null;
  const alert = staleAlert(meta?.generated, now, env.GITHUB_REPO);
  if (!alert) return;
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
