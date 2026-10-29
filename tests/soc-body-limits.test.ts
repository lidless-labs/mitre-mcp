import { afterEach, expect, it, vi } from "vitest";
import { CortexClient, MispClient, TheHiveClient, WazuhClient } from "../src/soc/client.js";
const clients = () => [
  new TheHiveClient({ url: "https://thehive.example.internal", apiKey: "secret-test" }),
  new CortexClient({ url: "https://cortex.example.internal", apiKey: "secret-test" }),
  new MispClient({ url: "https://misp.example.internal", apiKey: "secret-test", verifySsl: false }),
  new WazuhClient({ url: "https://wazuh.example.internal", username: "test", password: "secret-test", verifySsl: true }),
];
afterEach(() => vi.restoreAllMocks());
function body(chunks: string[], stalled = false) {
  const cancel = vi.fn();
  const stream = new ReadableStream<Uint8Array>({ start(c) { for (const text of chunks) c.enqueue(new TextEncoder().encode(text)); if (!stalled) c.close(); }, cancel });
  return { stream, cancel };
}
it.each([0, 1, 2, 3].flatMap(index => [true, false].map(declared => ({ index, declared }))))("caps successful response bytes for client $index, declared=$declared", async ({ index, declared }) => {
    const payload = body(declared ? [] : ['{"value":"', "x".repeat(700_000), "x".repeat(700_000), '"}'], declared);
    vi.spyOn(globalThis, "fetch").mockImplementation(async url => {
      if (String(url).includes("authenticate")) return Response.json({ data: { token: "test" } });
      return new Response(payload.stream, { headers: declared ? { "content-length": "2000000" } : {} });
    });
    const result = await clients()[index].request("GET", "/test");
    expect(result.ok).toBe(false); expect(JSON.stringify(result)).not.toContain("secret-test");
    if (declared) expect(payload.cancel).toHaveBeenCalled();
});
it.each([true, false])("bounds Wazuh authentication before parsing, declared=%s", async declared => {
  const payload = body(declared ? [] : ['{"data":{"token":"', "x".repeat(700_000), "x".repeat(700_000), '"}}'], declared);
  const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(payload.stream, { headers: declared ? { "content-length": "2000000" } : {} }));
  const result = await clients()[3].request("GET", "/test");
  expect(result.ok).toBe(false); if (declared) expect(payload.cancel).toHaveBeenCalled(); expect(fetch).toHaveBeenCalledTimes(1);
});
it.each([false, true])("enforces a total deadline through stalled %s response bodies", async auth => {
  const timeout = AbortSignal.timeout.bind(AbortSignal);
  vi.spyOn(AbortSignal, "timeout").mockImplementation(() => timeout(25));
  const payload = body(['{"secret-test":'], true);
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(payload.stream));
  const result = await clients()[auth ? 3 : 0].request("GET", "/test");
  expect(result.ok).toBe(false); expect(result.error).toMatch(/timed out/); expect(payload.cancel).toHaveBeenCalled();
  expect(JSON.stringify(result)).not.toContain("secret-test");
});
it("redacts partial body failures and rejection causes", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{"token":"secret-test')); c.error(new Error("secret-test", { cause: "secret-test" })); } })));
  expect(await clients()[0].request("GET", "/test")).toEqual({ ok: false, error: "SOC request failed." });
});
it("does not wait for hostile error-body cancellation", async () => {
  const stream = new ReadableStream({ cancel() { return new Promise(() => {}); } });
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(stream, { status: 503 }));
  expect(await clients()[0].request("GET", "/test")).toMatchObject({ ok: false, status: 503, error: "SOC request failed (HTTP 503)." });
});

it("shares one total deadline across Wazuh authentication and the following request", async () => {
  const timeout = AbortSignal.timeout.bind(AbortSignal);
  vi.spyOn(AbortSignal, "timeout").mockImplementation(() => timeout(60));
  const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(async url => {
    await new Promise(resolve => setTimeout(resolve, 40));
    return String(url).includes("authenticate") ? Response.json({ data: { token: "test" } }) : Response.json({ result: "ok" });
  });
  const result = await clients()[3].request("GET", "/test");
  expect(fetch).toHaveBeenCalledTimes(2); expect(result.ok).toBe(false); expect(result.error).toMatch(/timed out/);
});
