import { afterEach, describe, expect, it, vi } from "vitest";
import { dispatchPublish } from "../src/dispatch";
import worker from "../src/index";
import { setup } from "./harness";

vi.mock("cloudflare:email", () => ({ EmailMessage: class {} }));

const NOW = Date.parse("2026-11-01T06:00:00Z");
const health = (day: unknown) => Response.json({ ok: true, degraded: false, stale: [], feed: { day, age_s: 60 } });

function github(opts: { health?: () => Response; runs?: unknown[]; runsStatus?: number; dispatchStatus?: number } = {}) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    if (url.startsWith("https://mirage.offseq.com")) return (opts.health ?? (() => health("2026-11-01")))();
    if (url.endsWith("/runs?per_page=5"))
      return opts.runsStatus ? new Response("nope", { status: opts.runsStatus }) : Response.json({ workflow_runs: opts.runs ?? [] });
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
    const { calls } = github({ health: h });
    await dispatchPublish(env().env, NOW);
    expect(calls.filter((c) => c.url.startsWith("https://api.github.com"))).toEqual([]);
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

  it("logs and skips without a token", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const { calls } = github();
    await dispatchPublish(env(undefined, "").env, NOW);
    expect(calls.filter((c) => c.url.startsWith("https://api.github.com"))).toEqual([]);
    expect(error).toHaveBeenCalledTimes(1);
    expect(error).toHaveBeenCalledWith(expect.stringContaining("dispatch disabled"));
  });

  it("logs GitHub errors without throwing or leaking the token", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const { dispatched } = github({ dispatchStatus: 401 });
    await expect(dispatchPublish(env().env, NOW)).resolves.toBeUndefined();
    expect(dispatched()).toHaveLength(1);
    expect(error).toHaveBeenCalledWith(expect.stringContaining("401 Bad credentials"));
    expect(JSON.stringify(error.mock.calls)).not.toContain("ghp_secret");
  });

  it("skips the dispatch when the run list is unreadable", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const { dispatched } = github({ runsStatus: 500 });
    await dispatchPublish(env().env, NOW);
    expect(dispatched()).toEqual([]);
    expect(error).toHaveBeenCalledWith(expect.stringContaining("500"));
  });

  it("still runs the freshness check when dispatch throws", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    github();
    const sent: unknown[] = [];
    const ALERT = { send: async (m: unknown) => void sent.push(m) } as unknown as SendEmail;
    const { env: e } = setup({ ALERT });
    Object.defineProperty(e, "GH_DISPATCH_TOKEN", {
      get: () => {
        throw new Error("boom");
      },
    });
    await worker.scheduled({ scheduledTime: Date.parse("2026-11-01T07:00:00Z") } as ScheduledController, e);
    expect(error).toHaveBeenCalledWith("dispatch: failed", expect.any(Error));
    expect(sent).toHaveLength(1);
  });
});
