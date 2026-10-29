import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdtemp, readdir, readFile, symlink, chmod, open, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/index.js";
import { AttackDataStore } from "../src/data/index.js";
import { MispClient, TheHiveClient, CortexClient } from "../src/soc/client.js";
import type { MitreConfig } from "../src/types.js";
vi.mock("node:fs/promises", async importOriginal => {
  const original = await importOriginal<typeof import("node:fs/promises")>();
  return { ...original, open: vi.fn(original.open) };
});
let client: Client, server: ReturnType<typeof createMcpServer>, state: string, store: AttackDataStore;
async function connect(config: MitreConfig) {
  server = createMcpServer(config, store); client = new Client({ name: "replay", version: "1" });
  const [c, s] = InMemoryTransport.createLinkedPair(); await server.connect(s); await client.connect(c);
}
const config: MitreConfig = { dataDir: "/unused", matrices: ["enterprise"], updateInterval: 24, soc: {
  misp: { url: "https://misp.example.internal", apiKey: "test", verifySsl: true },
  thehive: { url: "https://thehive.example.internal", apiKey: "test" },
  cortex: { url: "https://cortex.example.internal", apiKey: "test" },
} };
const lanes = [
  { name: "mitre_misp_create_event", cls: MispClient, args: { info: "private-ioc", techniques: ["T1059"], attributes: [{ type: "domain", value: "private-ioc" }] } },
  { name: "mitre_thehive_create_case", cls: TheHiveClient, args: { title: "private-ioc", techniques: ["T1059"], observables: [{ dataType: "domain", data: "private-ioc" }] } },
  { name: "mitre_cortex_run_analyzers", cls: CortexClient, args: { data: "private-ioc", dataType: "domain" } },
];
beforeEach(async () => {
  state = await mkdtemp(join(tmpdir(), "mitre-replay-"));
  vi.stubEnv("MITRE_SOC_STATE_DIR", state); vi.stubEnv("MITRE_SOC_ALLOW_WRITES", "false");
  store = new AttackDataStore(config);
  vi.mocked(open).mockImplementation((await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises")).open);
  store.loadFromBundles(new Map([["enterprise", { type: "bundle", id: "bundle--test", objects: [{ type: "attack-pattern", id: "attack-pattern--test", name: "Command", external_references: [{ source_name: "mitre-attack", external_id: "T1059" }], kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "execution" }] }] }]]));
  for (const { cls } of lanes) vi.spyOn(cls.prototype, "request").mockImplementation(async (method) => ({ ok: true, data: method === "GET" ? [{ id: "a", name: "A" }, { id: "b", name: "B" }] : { id: "job-1", _id: "case-1", Event: { id: "1", uuid: "uuid-1" } } }) as never);
  await connect(config);
});
afterEach(async () => { await client.close(); await server.close(); vi.restoreAllMocks(); vi.unstubAllEnvs(); });
const call = (lane: typeof lanes[number], more = {}) => client.callTool({ name: lane.name, arguments: { ...lane.args, confirm: true, operationKey: "stable-key", ...more } });
for (const lane of lanes) {
  it(`${lane.name}: repeated calls reuse successful writes and reject key payload changes`, async () => {
    expect((await call(lane)).isError).not.toBe(true);
    const writes = () => vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST").length;
    const n = writes(); expect(n).toBeGreaterThan(1);
    expect((await call(lane)).isError).not.toBe(true); expect(writes()).toBe(n);
    expect((await call(lane, { techniques: ["T1059", "T9999"], data: "different", info: "different", title: "different" })).isError).toBe(true);
    expect(writes()).toBe(n);
    const files = await readdir(state, { recursive: true });
    for (const f of files.filter(f => f.endsWith(".json"))) expect(await readFile(join(state, f), "utf8")).not.toContain("private-ioc");
  });
  it.each([1, 2])(`${lane.name}: unknown step %s never repeats an attempted write`, async failedStep => {
    let n = 0;
    vi.mocked(lane.cls.prototype.request).mockImplementation(async (method) => {
      if (method === "GET") return { ok: true, data: [{ id: "a", name: "A" }, { id: "b", name: "B" }] } as never;
      if (++n === failedStep) throw new Error("secret transport cause");
      return { ok: true, data: { id: "job-1", _id: "case-1", Event: { id: "1", uuid: "uuid-1" } } } as never;
    });
    const first = await call(lane); expect(first.isError).toBe(true);
    expect(JSON.stringify(first)).toContain("uncertain"); expect(JSON.stringify(first)).not.toContain("secret transport cause");
    const retry = await call(lane); expect(retry.isError).toBe(true); expect(n).toBe(failedStep);
    expect(JSON.stringify(retry)).toContain("stable-key");
  });
  it(`${lane.name}: concurrent calls have one writer per step`, async () => {
    let release!: () => void;
    const gate = new Promise<void>(r => { release = r; });
    const original = vi.mocked(lane.cls.prototype.request).getMockImplementation()!;
    vi.mocked(lane.cls.prototype.request).mockImplementation(async (...args) => { if (args[0] === "POST") await gate; return original(...args); });
    const a = call(lane); await vi.waitFor(() => expect(vi.mocked(lane.cls.prototype.request).mock.calls.some(([method]) => method === "POST")).toBe(true));
    const b = await call(lane); expect(b.isError).toBe(true); release();
    expect((await a).isError).not.toBe(true);
    const posts = vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST");
    expect(new Set(posts.map(([, p, body]) => JSON.stringify([p, body]))).size).toBe(posts.length);
  });
  it(`${lane.name}: resumes a known missing step after a local failure before intent creation`, async () => {
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    let fail = true;
    vi.mocked(open).mockImplementation((...args) => {
      if (String(args[0]).endsWith("/1.intent.json") && fail) {
        fail = false;
        throw Object.assign(new Error("Local disk failure"), { code: "ENOSPC" });
      }
      return actual.open(...args);
    });
    expect((await call(lane)).isError).toBe(true);
    expect(vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST")).toHaveLength(1);
    expect((await call(lane)).isError).not.toBe(true);
    const posts = vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST");
    expect(posts.length).toBeGreaterThan(1);
    expect(new Set(posts.map(([, p, body]) => JSON.stringify([p, body]))).size).toBe(posts.length);
  });
  it(`${lane.name}: credential rotation and server restart retain the same operation`, async () => {
    expect((await call(lane)).isError).not.toBe(true);
    const n = vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST").length;
    await client.close(); await server.close();
    const rotated = structuredClone(config);
    for (const key of ["misp", "thehive", "cortex"] as const) { rotated.soc[key]!.apiKey = "rotated-test"; rotated.soc[key]!.url += "/"; }
    await connect(rotated);
    expect((await call(lane)).isError).not.toBe(true);
    expect(vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST")).toHaveLength(n);
  });
  it(`${lane.name}: dry runs do not touch state or network and writes require a key`, async () => {
    const dry = await call(lane, { confirm: false, operationKey: undefined }); expect(dry.isError).not.toBe(true);
    expect(lane.cls.prototype.request).not.toHaveBeenCalled(); expect(await readdir(state)).toEqual([]);
    expect((await call(lane, { operationKey: undefined })).isError).toBe(true);
    expect(lane.cls.prototype.request).not.toHaveBeenCalled();
  });
}
it("rejects symlinked and non-private state roots before network writes", async () => {
  const path = state + "-link"; await symlink(state, path); vi.stubEnv("MITRE_SOC_STATE_DIR", path);
  expect((await call(lanes[0])).isError).toBe(true);
  vi.stubEnv("MITRE_SOC_STATE_DIR", state); await chmod(state, 0o755);
  expect((await call(lanes[0])).isError).toBe(true); expect(MispClient.prototype.request).not.toHaveBeenCalled();
});

it("rejects a state root beneath a directory writable by other users", async () => {
  const root = join(state, "child"); await mkdir(root, { mode: 0o700 }); await chmod(state, 0o777);
  vi.stubEnv("MITRE_SOC_STATE_DIR", root);
  expect((await call(lanes[0])).isError).toBe(true); expect(MispClient.prototype.request).not.toHaveBeenCalled();
});
