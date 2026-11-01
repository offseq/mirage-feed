import { readHealth, readPublished } from "./alert";
import type { Env } from "./env";

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const ACTIVE = new Set(["queued", "in_progress", "waiting", "pending", "requested"]);
// Shorter than the hourly cron so a failed run is retried on the next tick.
const RECENT_MS = 50 * 60_000;

async function github(env: Env, path: string, init: RequestInit = {}): Promise<Response | null> {
  const url = `https://api.github.com/repos/${env.GITHUB_REPO}/actions/workflows/publish.yml/${path}`;
  try {
    const res = await fetch(url, {
      ...init,
      signal: AbortSignal.timeout(15_000),
      headers: {
        authorization: `Bearer ${env.GH_DISPATCH_TOKEN}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "mirage-feed-site",
      },
    });
    if (res.ok) return res;
    console.error(`dispatch: ${init.method ?? "GET"} ${path} -> ${res.status} ${(await res.text()).slice(0, 200)}`);
  } catch (e) {
    console.error(`dispatch: ${path} failed`, e);
  }
  return null;
}

async function runPending(env: Env, now: number): Promise<boolean> {
  const res = await github(env, "runs?per_page=5");
  if (!res) return true;
  const { workflow_runs: runs = [] } = (await res.json()) as { workflow_runs?: { status?: string; created_at?: string }[] };
  return runs.some((r) => ACTIVE.has(r.status ?? "") || now - Date.parse(r.created_at ?? "") < RECENT_MS);
}

export async function dispatchPublish(env: Env, now: number): Promise<void> {
  if (!env.GH_DISPATCH_TOKEN) {
    console.error("dispatch: GH_DISPATCH_TOKEN not set, publish dispatch disabled");
    return;
  }
  const day = (await readHealth())?.feed?.day;
  if (!day || !DAY.test(day)) return;
  const published = (await readPublished(env))?.day;
  // An unreadable pointer should not block a publish that would repair it.
  if (published && DAY.test(published) && day <= published) return;
  if (await runPending(env, now)) return;
  if (await github(env, "dispatches", { method: "POST", body: JSON.stringify({ ref: "main" }) })) console.log(`dispatch: publish ${day} (published ${published ?? "none"})`);
}
