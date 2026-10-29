import { randomUUID } from "node:crypto";
import { createServer, request } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createHttpServer, type HttpServerHandle } from "../src/http.js";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AttackDataStore } from "../src/data/index.js";

const TOKEN = randomUUID();
const env = {
  MITRE_MCP_HTTP_TOKEN: TOKEN,
  MITRE_MCP_HTTP_PORT: "0",
  MITRE_MCP_HTTP_HOST: undefined,
  WAZUH_URL: undefined,
  THEHIVE_URL: undefined,
  CORTEX_URL: undefined,
  MISP_URL: undefined,
  MITRE_SOC_ALLOW_WRITES: undefined,
};
let http: HttpServerHandle | undefined;
const dirs: string[] = [];
const connections: { client: Client; transport: StreamableHTTPClientTransport }[] = [];
afterEach(async () => {
  for (const { client, transport } of connections.splice(0)) {
    await transport.terminateSession().catch(() => undefined);
    await client.close();
  }
  await http?.close();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  http = undefined;

  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function configure(extra = {}) {
  for (const [name, value] of Object.entries({ ...env, ...extra })) vi.stubEnv(name, value);
}
async function start(extra = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), "mitre-http-"));
  dirs.push(dataDir);
  writeFileSync(join(dataDir, "enterprise-attack.json"), JSON.stringify({ type: "bundle", id: "bundle--test", objects: [{ type: "attack-pattern", id: "attack-pattern--test", name: "Test technique", external_references: [{ source_name: "mitre-attack", external_id: "T1001" }] }] }));
  writeFileSync(join(dataDir, "metadata.json"), JSON.stringify({ lastUpdated: new Date().toISOString(), matrices: ["enterprise"] }));
  configure({ MITRE_SOC_STATE_DIR: join(dataDir, "operations"), MITRE_DATA_DIR: dataDir, MITRE_MATRICES: "enterprise", ...extra });
  http = await createHttpServer();
  return `http://localhost:${http.port}`;
}
async function connect(url: string) {
  const transport = new StreamableHTTPClientTransport(new URL(`${url}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
  });
  const client = new Client({ name: "http-test", version: "1" });
  connections.push({ client, transport });
  await client.connect(transport);
  return { client, transport };
}

describe("authenticated Streamable HTTP", () => {
  it.each([undefined, "Bearer wrong-token"])("rejects invalid authentication: %s", async (authorization) => {
    const url = await start();
    const response = await fetch(`${url}/mcp`, { method: "POST", headers: authorization ? { authorization } : {} });
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe("Bearer");
    expect(await response.text()).toBe("Unauthorized");
  });

  it("exposes only liveness without authentication", async () => {
    const response = await fetch(`${await start()}/healthz`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ok" });
  });

  it("lists tools using the SDK client and terminates its session", async () => {
    const url = await start();
    const { client, transport } = await connect(url);
    const result = await client.listTools();
    expect(result.tools.length).toBeGreaterThan(0);
    for (const tool of result.tools) {
      expect(tool.inputSchema.$schema).toBeUndefined();
      expect(tool.outputSchema?.$schema).toBeUndefined();
    }
    expect(result.tools.some((t) => t.name === "mitre_data_version")).toBe(true);
    const id = transport.sessionId;
    expect(id).toBeTruthy();
    await transport.terminateSession();
    const stale = await fetch(`${url}/mcp`, {
      headers: { authorization: `Bearer ${TOKEN}`, "mcp-session-id": id!, accept: "text/event-stream" },
    });
    expect(stale.status).toBe(404);
  });

  it.each([
    { origin: "https://evil.example.com" },
    { origin: "null" },
    { origin: "http://localhost.evil.example.com" },
    { host: "evil.example.com" },
    { host: "localhost@evil.example.com" },
  ])("rejects rebinding headers %j", async (headers) => {
    const url = await start();
    const status = await new Promise<number | undefined>((resolve, reject) => {
      const req = request(`${url}/mcp`, { method: "POST", headers: { ...headers, authorization: `Bearer ${TOKEN}` } }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      });
      req.on("error", reject);
      req.end();
    });
    expect(status).toBe(403);
  });

  it("accepts a loopback Origin", async () => {
    const url = await start();
    const response = await fetch(`${url}/mcp`, { method: "POST", headers: { origin: url } });
    expect(response.status).toBe(401);
  });

  it.each([undefined, "", "   "])("refuses missing or blank tokens", async (token) => {
    configure({ MITRE_MCP_HTTP_TOKEN: token });
    await expect(createHttpServer()).rejects.toThrow(/MITRE_MCP_HTTP_TOKEN/);
  });

  it.each(["WAZUH_PASSWORD", "WAZUH_USERNAME", "THEHIVE_API_KEY", "CORTEX_API_KEY", "MISP_API_KEY"])("refuses reuse of %s", async (name) => {
    configure({ [name]: TOKEN });
    await expect(createHttpServer()).rejects.toThrow(/MITRE_MCP_HTTP_TOKEN/);
  });

  it("refuses upstream URL and Basic credentials", async () => {
    configure({ WAZUH_URL: `https://reader:${TOKEN}@soc.example.com` });
    await expect(createHttpServer()).rejects.toThrow(/MITRE_MCP_HTTP_TOKEN/);
    configure({ WAZUH_URL: "https://soc.example.com", WAZUH_USERNAME: "reader", WAZUH_PASSWORD: "test-password-at-least-32-characters", MITRE_MCP_HTTP_TOKEN: Buffer.from("reader:test-password-at-least-32-characters").toString("base64") });
    await expect(createHttpServer()).rejects.toThrow(/MITRE_MCP_HTTP_TOKEN/);
  });

  it("refuses a token shorter than 32 characters", async () => {
    configure({ MITRE_MCP_HTTP_TOKEN: "a".repeat(31) });
    await expect(createHttpServer()).rejects.toThrow(/at least 32 characters/);
  });

  it.each(["0.0.0.0", "::", "[::]"])("refuses wildcard bind host %s", async (host) => {
    await expect(start({ MITRE_MCP_HTTP_HOST: host })).rejects.toThrow(/not a wildcard/);
  });

  it("accepts a token with surrounding whitespace from a secrets file", async () => {
    const url = await start({ MITRE_MCP_HTTP_TOKEN: `  ${TOKEN}\n` });
    const { client } = await connect(url);
    expect((await client.listTools()).tools.some((tool) => tool.name === "mitre_data_version")).toBe(true);
  });

  it.each(["-1", "65536", "abc", "3000suffix", "1.5"])("refuses invalid port %s", async (port) => {
    configure({ MITRE_MCP_HTTP_PORT: port });
    await expect(createHttpServer()).rejects.toThrow(/MITRE_MCP_HTTP_PORT/);
  });

  it("limits request bytes before JSON parsing", async () => {
    const url = await start();
    const response = await fetch(`${url}/mcp`, {
      method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: "x".repeat(1_048_577),
    });
    expect(response.status).toBe(413);
  });

  it("limits chunked bodies without a Content-Length", async () => {
    const url = await start();
    const status = await new Promise<number | undefined>((resolve, reject) => {
      const req = request(`${url}/mcp`, {
        method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      });
      req.on("error", reject);
      req.write("x".repeat(600_000));
      req.end("x".repeat(600_000));
    });
    expect(status).toBe(413);
  });

  it("expires idle sessions even with an SSE channel open", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const url = await start();
    const { transport } = await connect(url);
    const id = transport.sessionId!;
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 31 * 60_000);
    await vi.advanceTimersByTimeAsync(60_000);
    const response = await fetch(`${url}/mcp`, {
      headers: { authorization: `Bearer ${TOKEN}`, "mcp-session-id": id, accept: "text/event-stream" },
    });
    expect(response.status).toBe(404);
  });

  it("loads the dataset once for concurrent sessions and isolates connection lifetimes", async () => {
    const initialize = vi.spyOn(AttackDataStore.prototype, "initialize");
    const url = await start();
    const [a, b] = await Promise.all([connect(url), connect(url)]);
    expect(initialize).toHaveBeenCalledTimes(1);
    expect(a.transport.sessionId).not.toBe(b.transport.sessionId);
    await a.transport.terminateSession();
    expect((await b.client.listTools()).tools.some((t) => t.name === "mitre_update_data")).toBe(true);
    expect((await b.client.callTool({ name: "mitre_data_version", arguments: {} })).isError).not.toBe(true);
  });

  it("shares one update between sessions while readers keep the previous snapshot", async () => {
    const url = await start();
    const [a, b] = await Promise.all([connect(url), connect(url)]);
    const originalFetch = globalThis.fetch;
    let release!: (response: Response) => void;
    const download = vi.fn(() => new Promise<Response>((resolve) => { release = resolve; }));
    vi.stubGlobal("fetch", (input: Parameters<typeof fetch>[0], init: Parameters<typeof fetch>[1]) =>
      String(input).startsWith("https://raw.githubusercontent.com/mitre-attack/") ? download() : originalFetch(input, init));
    try {
      const updates = [a.client, b.client].map((client) => client.callTool({ name: "mitre_update_data", arguments: {} }));
      await vi.waitFor(() => expect(download).toHaveBeenCalledTimes(1));
      expect((await b.client.callTool({ name: "mitre_get_technique", arguments: { techniqueId: "T1001" } })).isError).not.toBe(true);
      release(Response.json({ type: "bundle", id: "bundle--empty", objects: [] }));
      expect((await Promise.all(updates)).every((result) => !result.isError)).toBe(true);
      expect(download).toHaveBeenCalledTimes(1);
      for (const client of [a.client, b.client]) {
        expect((await client.callTool({ name: "mitre_get_technique", arguments: { techniqueId: "T1001" } })).isError).toBe(true);
      }
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("never shares a confirmed SOC write with another call or session", async () => {
    const writes: string[] = [];
    const upstream = createServer((req, res) => {
      writes.push(req.url!);
      req.resume();
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ _id: "case-test" }));
    });
    await new Promise<void>((resolve) => upstream.listen(0, "localhost", resolve));
    const address = upstream.address();
    if (!address || typeof address === "string") throw new Error("No upstream port");
    try {
      const url = await start({ THEHIVE_URL: `http://localhost:${address.port}`, THEHIVE_API_KEY: "test-upstream-key" });
      const [a, b] = await Promise.all([connect(url), connect(url)]);
      const args = { title: "Test incident", techniques: ["T1001"], operationKey: "http-isolation" };
      const confirmed = await a.client.callTool({ name: "mitre_thehive_create_case", arguments: { ...args, confirm: true } });
      expect(confirmed.isError).not.toBe(true);
      for (const client of [a.client, b.client]) {
        const result = await client.callTool({ name: "mitre_thehive_create_case", arguments: args });
        expect(JSON.parse((result.content as { text: string }[])[0].text).dryRun).toBe(true);
      }
      expect(writes).toEqual(["/api/v1/case"]);
    } finally {
      upstream.closeAllConnections();
      await new Promise<void>((resolve, reject) => upstream.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("does not log upstream URL credentials when sessions initialize", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const url = await start({ WAZUH_URL: "https://reader:test-url-password@soc.example.com" });
    await Promise.all([connect(url), connect(url)]);
    expect(log.mock.calls.flat().join(" ")).not.toContain("test-url-password");
  });

  it("closes active sessions and the listener idempotently", async () => {
    const url = await start();
    await connect(url);
    await Promise.all([http!.close(), http!.close()]);
    await expect(fetch(`${url}/healthz`)).rejects.toThrow();
  });
});
