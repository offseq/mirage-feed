import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ALERT_AFTER_H, checkFreshness, staleAlert } from "../src/alert";
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

describe("staleness alert", () => {
  const built = "2026-10-24T03:05:00Z";
  const at = (h: number) => Date.parse(built) + h * 3_600_000;
  const healthy = { ok: true, degraded: false, stale: [], feed: { day: "2026-10-23", age_s: 3600 } };
  const repo = "offseq/mirage-feed";

  it("stays quiet while the feed and the backend are fresh", () => {
    expect(staleAlert(built, healthy, at(ALERT_AFTER_H - 1), repo)).toBeNull();
  });

  it("mails in the first stale hour, then only at the repeat hours", () => {
    expect(staleAlert(built, healthy, at(ALERT_AFTER_H), repo)?.subject).toBe(`Mirage Feed is stale (${ALERT_AFTER_H} h)`);
    expect(staleAlert(built, healthy, at(ALERT_AFTER_H + 1), repo)).toBeNull();
    const alert = staleAlert(built, healthy, Date.parse("2026-10-26T07:00:00Z"), repo);
    expect(alert?.subject).toBe("Mirage Feed is stale (51 h)");
    expect(alert?.body).toContain("https://github.com/offseq/mirage-feed/actions/workflows/publish.yml");
  });

  it("alerts at the repeat hours when the pointer is unreadable", () => {
    expect(staleAlert(undefined, healthy, Date.parse("2026-10-24T19:00:00Z"), repo)?.subject).toBe("Mirage Feed is stale");
    expect(staleAlert(undefined, healthy, Date.parse("2026-10-24T20:00:00Z"), repo)).toBeNull();
  });

  it("reports backend trouble while the published feed is still fresh", () => {
    const now = Date.parse("2026-10-24T19:00:00Z");
    const alert = staleAlert(built, { ...healthy, degraded: true, feed: { day: "2026-10-22", age_s: 40 * 3600 } }, now, repo);
    expect(alert?.subject).toBe("Mirage Feed backend needs attention");
    expect(alert?.body).toContain("degraded=true");
    expect(alert?.body).toContain("newest backend snapshot: 2026-10-22");
    expect(staleAlert(built, null, now, repo)?.body).toContain("did not answer");
  });
});

describe("scheduled freshness check", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });
  beforeEach(() =>
    vi.stubGlobal("fetch", async () => Response.json({ ok: true, degraded: false, stale: [], feed: { day: "2026-10-24", age_s: 60 } })),
  );

  const mailer = () => {
    const sent: { from: string; to: string; raw: string }[] = [];
    return { sent, ALERT: { send: async (m: (typeof sent)[number]) => void sent.push(m) } as unknown as SendEmail };
  };

  it("mails nothing while published.json is fresh", async () => {
    const { sent, ALERT } = mailer();
    const { env, r2 } = setup({ ALERT });
    r2.put("_meta/published.json", JSON.stringify({ generated: "2026-10-24T03:05:00Z" }));
    await checkFreshness(env, Date.parse("2026-10-24T19:00:00Z"));
    expect(sent).toEqual([]);
  });

  it.each([
    ["missing", (_: ReturnType<typeof setup>["r2"]) => {}],
    ["not JSON", (r2: ReturnType<typeof setup>["r2"]) => r2.put("_meta/published.json", "{")],
    ["unreachable", (r2: ReturnType<typeof setup>["r2"]) => void (r2.failing = true)],
  ])("mails when published.json is %s", async (_, arrange) => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { sent, ALERT } = mailer();
    const { env, r2 } = setup({ ALERT });
    arrange(r2);
    await checkFreshness(env, Date.parse("2026-10-24T19:00:00Z"));
    expect(sent).toHaveLength(1);
    expect(sent[0].to).toBe("ops@example.org");
    expect(sent[0].raw).toContain("Subject: Mirage Feed is stale\r\n");
  });

  it("logs a stale feed it cannot mail about", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await checkFreshness(setup().env, Date.parse("2026-10-24T19:00:00Z"));
    expect(error).toHaveBeenCalledWith(expect.stringContaining("no ALERT binding"));
  });

  it("logs and rethrows a failed send from the cron handler", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const ALERT = { send: async () => Promise.reject(new Error("destination not verified")) } as unknown as SendEmail;
    const { env } = setup({ ALERT });
    const event = { scheduledTime: Date.parse("2026-10-24T19:00:00Z") } as ScheduledController;
    await expect(worker.scheduled(event, env)).rejects.toThrow("destination not verified");
    expect(error).toHaveBeenCalledWith("freshness: alert not sent", expect.any(Error));
  });
});
