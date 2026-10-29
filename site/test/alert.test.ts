import { afterEach, describe, expect, it, vi } from "vitest";
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

  it("stays quiet while the feed is fresh", () => {
    expect(staleAlert(built, at(ALERT_AFTER_H - 1), "offseq/mirage-feed")).toBeNull();
  });

  it("names the age and links the publish runs once stale", () => {
    const alert = staleAlert(built, at(55), "offseq/mirage-feed");
    expect(alert?.subject).toBe("Mirage Feed is stale (55 h)");
    expect(alert?.body).toContain("https://github.com/offseq/mirage-feed/actions/workflows/publish.yml");
  });

  it("alerts when the pointer is missing or unreadable", () => {
    expect(staleAlert(undefined, at(0), "offseq/mirage-feed")?.subject).toBe("Mirage Feed is stale");
  });
});

describe("scheduled freshness check", () => {
  afterEach(() => vi.restoreAllMocks());

  const mailer = () => {
    const sent: { from: string; to: string; raw: string }[] = [];
    return { sent, ALERT: { send: async (m: (typeof sent)[number]) => void sent.push(m) } as unknown as SendEmail };
  };

  it("mails nothing while published.json is fresh", async () => {
    const { sent, ALERT } = mailer();
    const { env, r2 } = setup({ ALERT });
    r2.put("_meta/published.json", JSON.stringify({ generated: "2026-10-24T03:05:00Z" }));
    await checkFreshness(env, Date.parse("2026-10-24T20:00:00Z"));
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
    await checkFreshness(env, Date.parse("2026-10-24T20:00:00Z"));
    expect(sent).toHaveLength(1);
    expect(sent[0].to).toBe("ops@example.org");
    expect(sent[0].raw).toContain("Subject: Mirage Feed is stale\r\n");
  });

  it("logs a stale feed it cannot mail about", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await checkFreshness(setup().env, Date.parse("2026-10-24T20:00:00Z"));
    expect(error).toHaveBeenCalledWith(expect.stringContaining("no ALERT binding"));
  });

  it("logs and rethrows a failed send from the cron handler", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const ALERT = { send: async () => Promise.reject(new Error("destination not verified")) } as unknown as SendEmail;
    const { env } = setup({ ALERT });
    const event = { scheduledTime: Date.parse("2026-10-24T20:00:00Z") } as ScheduledController;
    await expect(worker.scheduled(event, env)).rejects.toThrow("destination not verified");
    expect(error).toHaveBeenCalledWith("freshness: alert not sent", expect.any(Error));
  });
});
