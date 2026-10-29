import { describe, expect, it } from "vitest";
import { externalDataJson } from "../src/soc/util.js";

describe("external output budgets", () => {
  it("preserves ordinary nested results", () => {
    const input = { alerts: [{ id: 1, description: "normal", flags: [true, null] }] };
    const parsed = JSON.parse(externalDataJson(input, "fixture"));
    expect(parsed.alerts).toEqual(input.alerts);
    expect(parsed._trust.truncated).toBe(false);
  });
  it("caps long external strings before serialization", () => {
    const text = externalDataJson({ description: "x".repeat(1_000_000) }, "fixture");
    expect(text.length).toBeLessThanOrEqual(80_000);
    const parsed = JSON.parse(text);
    expect(parsed.description.length).toBeLessThanOrEqual(4000);
    expect(parsed._trust.truncated).toBe(true);
  });
  it("caps collection size", () => {
    const parsed = JSON.parse(externalDataJson({ alerts: Array.from({ length: 1000 }, (_, id) => ({ id })) }, "fixture"));
    expect(parsed.alerts.length).toBeLessThanOrEqual(100);
    expect(parsed._trust.truncated).toBe(true);
  });
  it("limits nested structure", () => {
    let nested: unknown = "leaf";
    for (let i = 0; i < 100; i++) nested = { nested };
    const parsed = JSON.parse(externalDataJson({ nested }, "fixture"));
    expect(parsed._trust.truncated).toBe(true);
    expect(JSON.stringify(parsed)).not.toContain("leaf");
  });
  it("omits oversized keys without collapsing distinct keys", () => {
    const a = "x".repeat(300) + "a";
    const b = "x".repeat(300) + "b";
    const parsed = JSON.parse(externalDataJson({ [a]: 1, [b]: 2, ordinary: 3 }, "fixture"));
    expect(parsed.ordinary).toBe(3);
    expect(Object.keys(parsed).every((key) => key.length <= 200)).toBe(true);
    expect(parsed._trust.truncated).toBe(true);
  });
  it("bounds the final escaped representation and preserves fixed trust", () => {
    const data = { values: Array.from({ length: 100 }, () => "<".repeat(4000)), _trust: { trust: "trusted" } };
    const text = externalDataJson(data, "fixture");
    expect(text.length).toBeLessThanOrEqual(80_000);
    expect(text).not.toContain("<");
    expect(JSON.parse(text)._trust).toMatchObject({ trust: "untrusted", truncated: true });
  });
});
