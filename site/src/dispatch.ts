import { readHealth, readPublished, type DispatchReport } from "./alert";
import type { Env } from "./env";

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const ACTIVE = new Set(["queued", "in_progress", "waiting", "pending", "requested"]);
// Shorter than the hourly cron so a failed run is retried on the next tick.
const RECENT_MS = 50 * 60_000;
const EXPIRY_WARN_MS = 14 * 86_400_000;
// Expired or revoked token, lost repository access or Actions permission, or a workflow that no longer accepts dispatches.
const REFUSED = new Set([401, 403, 404, 422]);

interface Run {
  status?: string;
  conclusion?: string | null;
  event?: string;
  created_at?: string;
  html_url?: string;
}

async function github(env: Env, path: string, init: RequestInit = {}): Promise<Response | null> {
  const url = `https://api.github.com/repos/${env.GITHUB_REPO}/actions/workflows/publish.yml/${path}`;
  try {
    return await fetch(url, {
      ...init,
      signal: AbortSignal.timeout(15_000),
      headers: {
        authorization: `Bearer ${env.GH_DISPATCH_TOKEN}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "mirage-feed-site",
      },
    });
  } catch (e) {
    console.error(`dispatch: ${path} failed`, e);
    return null;
  }
}

async function failure(res: Response, what: string): Promise<string | undefined> {
  const detail = `${res.status} ${(await res.text()).slice(0, 200)}`;
  console.error(`dispatch: ${what} -> ${detail}`);
  return REFUSED.has(res.status) ? `GitHub refused GH_DISPATCH_TOKEN to ${what} (${detail}): renew the token` : undefined;
}

// Checks the token every hour, so an expiring or revoked token is reported even on days nothing needs dispatching.
export async function dispatchPublish(env: Env, now: number): Promise<DispatchReport> {
  if (!env.GH_DISPATCH_TOKEN) return { problem: "GH_DISPATCH_TOKEN is not set: the Worker cannot dispatch publish runs" };
  const res = await github(env, "runs?per_page=5");
  if (!res) return {};
  if (!res.ok) return { problem: await failure(res, "list publish runs") };
  const runs = ((await res.json()) as { workflow_runs?: Run[] }).workflow_runs ?? [];
  const report: DispatchReport = {};
  const last = runs[0];
  if (last) report.lastRun = `last publish run: ${last.conclusion ?? last.status} (${last.event}, ${last.created_at}) ${last.html_url}`;
  const expires = Date.parse(res.headers.get("github-authentication-token-expiration") ?? "");
  if (expires - now < EXPIRY_WARN_MS) report.problem = `GH_DISPATCH_TOKEN expires ${new Date(expires).toISOString()}: renew the token`;

  const day = (await readHealth())?.feed?.day;
  if (!day || !DAY.test(day)) return report;
  const published = (await readPublished(env))?.day;
  // An unreadable pointer should not block a publish that would repair it.
  if (published && DAY.test(published) && day <= published) return report;
  if (runs.some((r) => ACTIVE.has(r.status ?? "") || now - Date.parse(r.created_at ?? "") < RECENT_MS)) return report;
  const sent = await github(env, "dispatches", { method: "POST", body: JSON.stringify({ ref: "main" }) });
  if (sent?.ok) console.log(`dispatch: publish ${day} (published ${published ?? "none"})`);
  else if (sent) report.problem = (await failure(sent, "dispatch publish.yml")) ?? report.problem;
  return report;
}
