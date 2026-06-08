import { describe, it, expect, afterEach } from "vitest";
import { safePathSegment, encodeSegment, writesAllowed } from "../src/soc/util.js";

describe("safePathSegment (API-route injection defense)", () => {
  it("accepts numeric IDs", () => {
    expect(safePathSegment("12345", "eventId")).toBe("12345");
  });

  it("accepts TheHive/MISP object-style IDs", () => {
    expect(safePathSegment("~h_case_42", "caseId")).toBe("~h_case_42");
    expect(safePathSegment("a1b2-c3d4.e5", "id")).toBe("a1b2-c3d4.e5");
  });

  it("rejects path traversal / route pivots", () => {
    expect(() => safePathSegment("../../api/admin", "caseId")).toThrow(/Invalid caseId/);
    expect(() => safePathSegment("1/observable", "caseId")).toThrow(/Invalid caseId/);
  });

  it("rejects query-string injection", () => {
    expect(() => safePathSegment("1&min_level=0", "agentId")).toThrow(/Invalid agentId/);
    expect(() => safePathSegment("1?x=y", "id")).toThrow();
  });

  it("rejects whitespace and empty values", () => {
    expect(() => safePathSegment("", "id")).toThrow();
    expect(() => safePathSegment("a b", "id")).toThrow();
  });

  it("rejects encoded-separator smuggling", () => {
    // %2F decodes to "/"; the raw "%" is not in the allow-list, so it is rejected
    // before it can be double-decoded by the server into a path separator.
    expect(() => safePathSegment("1%2Fobservable", "caseId")).toThrow();
  });

  it("rejects over-long values", () => {
    expect(() => safePathSegment("a".repeat(257), "id")).toThrow(/too long/);
  });
});

describe("encodeSegment", () => {
  it("percent-encodes URL-unsafe characters", () => {
    expect(encodeSegment("a b/c")).toBe("a%20b%2Fc");
  });
});

describe("writesAllowed (state-change confirmation guard)", () => {
  const prev = process.env.MITRE_SOC_ALLOW_WRITES;
  afterEach(() => {
    if (prev === undefined) delete process.env.MITRE_SOC_ALLOW_WRITES;
    else process.env.MITRE_SOC_ALLOW_WRITES = prev;
  });

  it("defaults to false (dry-run) with no confirm and no env", () => {
    delete process.env.MITRE_SOC_ALLOW_WRITES;
    expect(writesAllowed()).toBe(false);
    expect(writesAllowed(false)).toBe(false);
  });

  it("allows when confirm=true", () => {
    delete process.env.MITRE_SOC_ALLOW_WRITES;
    expect(writesAllowed(true)).toBe(true);
  });

  it("allows when env opt-in is set", () => {
    process.env.MITRE_SOC_ALLOW_WRITES = "true";
    expect(writesAllowed()).toBe(true);
    process.env.MITRE_SOC_ALLOW_WRITES = "1";
    expect(writesAllowed()).toBe(true);
  });

  it("ignores non-truthy env values", () => {
    process.env.MITRE_SOC_ALLOW_WRITES = "no";
    expect(writesAllowed()).toBe(false);
    process.env.MITRE_SOC_ALLOW_WRITES = "0";
    expect(writesAllowed()).toBe(false);
  });
});
