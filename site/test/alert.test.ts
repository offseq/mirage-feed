import { describe, expect, it } from "vitest";
import { ALERT_AFTER_H, staleAlert } from "../src/alert";

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
