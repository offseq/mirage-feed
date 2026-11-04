import { afterEach, describe, expect, it, vi } from "vitest";
import { dispatchPublish } from "../src/dispatch";
import worker from "../src/index";
import { setup } from "./harness";

vi.mock("cloudflare:email", () => ({
  EmailMessage: class {
    constructor(
      readonly from: string,
      readonly to: string,
      readonly raw: string,
    ) {}
  },
}));

const NOW = Date.parse("2026-11-01T06:00:00Z");
const health = (day: unknown) => Response.json({ ok: true, degraded: false, stale: [], feed: { day, age_s: 60 } });

function github(
  opts: { health?: () => Response; runs?: unknown[]; runsStatus?: number; dispatchStatus?: number; expires?: string } = {},
) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    if (url.startsWith("https://mirage.offseq.com")) return (opts.health ?? (() => health("2026-11-01")))();
    if (url.endsWith("/runs?per_page=5"))
      return opts.runsStatus
        ? new Response("Bad credentials", { status: opts.runsStatus })
        : Response.json({ workflow_runs: opts.runs ?? [] }, { headers: opts.expires ? { "github-authentication-token-expiration": opts.expires } : {} });
    return new Response(opts.dispatchStatus === undefined ? null : "Bad credentials", { status: opts.dispatchStatus ?? 204 });
  });
  const dispatched = () => calls.filter((c) => c.url.endsWith("/dispatches"));
  return { calls, dispatched };
}

const env = (published: unknown = { generated: "2026-10-31T03:05:00Z", day: "2026-10-31" }, token = "ghp_secret") => {
  const s = setup({ GH_DISPATCH_TOKEN: token });
  if (published !== undefined) s.r2.put("_meta/published.json", JSON.stringify(published));
  return s;
};

describe("publish dispatch", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("dispatches publish.yml when the backend has a newer day", async () => {
    const { dispatched } = github({ runs: [{ status: "completed", created_at: "2026-11-01T04:00:00Z" }] });
    vi.spyOn(console, "log").mockImplementation(() => {});
    await dispatchPublish(env().env, NOW);
    const [call] = dispatched();
    expect(call.url).toBe("https://api.github.com/repos/offseq/mirage-feed/actions/workflows/publish.yml/dispatches");
    expect(call.init?.method).toBe("POST");
    expect(call.init?.body).toBe('{"ref":"main"}');
    expect(call.init?.headers).toMatchObject({
      authorization: "Bearer ghp_secret",
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "mirage-feed-site",
    });
  });

  it.each([
    ["equal", () => health("2026-10-31")],
    ["older", () => health("2026-10-30")],
    ["missing", () => health(null)],
    ["malformed", () => health("2026-11-1")],
    ["unreadable", () => new Response("down", { status: 503 })],
  ])("does not dispatch when the backend day is %s", async (_, h) => {
    const { dispatched } = github({ health: h });
    expect(await dispatchPublish(env().env, NOW)).toEqual({});
    expect(dispatched()).toEqual([]);
  });

  it("dispatches when published.json is unreadable", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { dispatched } = github();
    await dispatchPublish(env(undefined).env, NOW);
    expect(dispatched()).toHaveLength(1);
  });

  it.each([
    ["in progress", { status: "in_progress", created_at: "2026-11-01T02:00:00Z" }],
    ["queued", { status: "queued", created_at: "2026-11-01T02:00:00Z" }],
    ["recent", { status: "completed", created_at: "2026-11-01T05:20:00Z" }],
  ])("skips when a run is %s", async (_, run) => {
    const { dispatched } = github({ runs: [run] });
    await dispatchPublish(env().env, NOW);
    expect(dispatched()).toEqual([]);
  });

  it("reports a missing token without calling GitHub", async () => {
    const { calls } = github();
    expect((await dispatchPublish(env(undefined, "").env, NOW)).problem).toContain("GH_DISPATCH_TOKEN is not set");
    expect(calls.filter((c) => c.url.startsWith("https://api.github.com"))).toEqual([]);
  });

  it("reports a refused dispatch without throwing or leaking the token", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const { dispatched } = github({ dispatchStatus: 401 });
    const report = await dispatchPublish(env().env, NOW);
    expect(dispatched()).toHaveLength(1);
    expect(report.problem).toContain("401 Bad credentials");
    expect(error).toHaveBeenCalledWith(expect.stringContaining("401 Bad credentials"));
    expect(JSON.stringify([report, error.mock.calls])).not.toContain("ghp_secret");
  });

  it("checks the token every hour, even with nothing to dispatch", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    github({ health: () => health("2026-10-31"), runsStatus: 401 });
    expect((await dispatchPublish(env().env, NOW)).problem).toContain("GitHub refused GH_DISPATCH_TOKEN to list publish runs (401");
  });

  it("warns two weeks before the token expires", async () => {
    github({ health: () => health("2026-10-31"), expires: "2026-11-10 00:00:00 UTC" });
    expect((await dispatchPublish(env().env, NOW)).problem).toBe("GH_DISPATCH_TOKEN expires 2026-11-10T00:00:00.000Z: renew the token");
    github({ health: () => health("2026-10-31"), expires: "2026-12-31 00:00:00 UTC" });
    expect(await dispatchPublish(env().env, NOW)).toEqual({});
  });

  it("describes the last run for the alert", async () => {
    const run = { status: "completed", conclusion: "failure", event: "schedule", created_at: "2026-11-01T02:00:00Z", html_url: "https://github.com/r/1" };
    github({ health: () => health("2026-10-31"), runs: [run] });
    expect((await dispatchPublish(env().env, NOW)).lastRun).toBe("last publish run: failure (schedule, 2026-11-01T02:00:00Z) https://github.com/r/1");
  });

  it("skips the dispatch quietly when GitHub fails transiently", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const { dispatched } = github({ runsStatus: 500 });
    expect(await dispatchPublish(env().env, NOW)).toEqual({ problem: undefined });
    expect(dispatched()).toEqual([]);
    expect(error).toHaveBeenCalledWith(expect.stringContaining("500"));
  });

  it("still runs the freshness check when dispatch throws", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    github();
    const sent: { raw: string }[] = [];
    const ALERT = { send: async (m: { raw: string }) => void sent.push(m) } as unknown as SendEmail;
    const { env: e } = setup({ ALERT });
    Object.defineProperty(e, "GH_DISPATCH_TOKEN", {
      get: () => {
        throw new Error("boom");
      },
    });
    await worker.scheduled({ scheduledTime: Date.parse("2026-11-01T07:00:00Z") } as ScheduledController, e);
    expect(error).toHaveBeenCalledWith("dispatch: failed", expect.any(Error));
    expect(sent).toHaveLength(1);
    expect(sent[0].raw).toContain("publish dispatch crashed: Error: boom");
  });
});
