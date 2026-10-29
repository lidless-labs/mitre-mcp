import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdtemp, readdir, readFile, symlink, chmod, open, mkdir, writeFile, unlink } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/index.js";
import { AttackDataStore } from "../src/data/index.js";
import { MispClient, TheHiveClient, CortexClient } from "../src/soc/client.js";
import type { MitreConfig } from "../src/types.js";
vi.mock("node:fs/promises", async importOriginal => {
  const original = await importOriginal<typeof import("node:fs/promises")>();
  return { ...original, open: vi.fn(original.open), mkdir: vi.fn(original.mkdir) };
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
  vi.mocked(mkdir).mockImplementation((await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises")).mkdir);
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
    if (failedStep === 2) expect(JSON.stringify(first)).toContain(expectedId(lane));
    const retry = await call(lane); expect(retry.isError).toBe(true); expect(n).toBe(failedStep);
    if (failedStep === 2) expect(JSON.stringify(retry)).toContain(expectedId(lane));
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

it("rejects relative state paths rather than changing operation identity with the working directory", async () => {
  vi.stubEnv("MITRE_SOC_STATE_DIR", relative(process.cwd(), state));
  expect((await call(lanes[0])).isError).toBe(true);
  expect(MispClient.prototype.request).not.toHaveBeenCalled(); expect(await readdir(state)).toEqual([]);
});

it.each([false, true])("persists the full directory ancestry before POST (mkdir EEXIST race: %s)", async race => {
  const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  const root = join(state, "new-parent", "new-root");
  vi.stubEnv("MITRE_SOC_STATE_DIR", root);
  const events: string[] = [];
  vi.mocked(mkdir).mockImplementation(async (...args) => {
    const result = await actual.mkdir(...args);
    events.push(`mkdir:${args[0]}`);
    // Model another same-user process winning mkdir, before persisting its parent.
    if (race) throw Object.assign(new Error("exists"), { code: "EEXIST" });
    return result;
  });
  vi.mocked(open).mockImplementation(async (...args) => {
    const handle = await actual.open(...args);
    const sync = handle.sync.bind(handle);
    vi.spyOn(handle, "sync").mockImplementation(async () => { await sync(); events.push(`sync:${args[0]}`); });
    return handle;
  });
  const request = vi.mocked(MispClient.prototype.request).getMockImplementation()!;
  vi.mocked(MispClient.prototype.request).mockImplementation(async (...args) => { events.push("POST"); return request(...args); });
  expect((await call(lanes[0])).isError).not.toBe(true);
  const beforePost = events.slice(0, events.indexOf("POST"));
  const [operationId] = await readdir(root);
  for (let path = join(root, operationId); ; path = dirname(path)) {
    const parent = dirname(path);
    expect(beforePost).toContain(`sync:${parent}`);
    if (beforePost.includes(`mkdir:${path}`)) expect(beforePost.lastIndexOf(`sync:${parent}`)).toBeGreaterThan(beforePost.indexOf(`mkdir:${path}`));
    if (parent === path) break;
  }
});

it.each(["ancestor", "root-parent", "operation-parent"])("directory sync failure at %s prevents every remote write", async level => {
  const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  const root = join(state, "new-parent", "new-root");
  vi.stubEnv("MITRE_SOC_STATE_DIR", root);
  const fault = level === "ancestor" ? state : level === "root-parent" ? dirname(root) : root;
  vi.mocked(open).mockImplementation(async (...args) => {
    const handle = await actual.open(...args);
    if (String(args[0]) === fault) vi.spyOn(handle, "sync").mockRejectedValue(Object.assign(new Error("unsupported directory sync"), { code: "EINVAL" }));
    return handle;
  });
  expect((await call(lanes[0])).isError).toBe(true);
  expect(MispClient.prototype.request).not.toHaveBeenCalled();
});

// The tool boundary owns retry semantics, including changing discovery/store data.
const expectedId = (lane: typeof lanes[number]) => lane.cls === MispClient ? "uuid-1" : lane.cls === TheHiveClient ? "case-1" : "job-1";
async function failBeforeIntent(step = 1) {
  const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  let once = true;
  vi.mocked(open).mockImplementation((...args) => {
    if (String(args[0]).endsWith(`/${step}.intent.json`) && once) {
      once = false;
      throw Object.assign(new Error("disk full before intent"), { code: "ENOSPC" });
    }
    return actual.open(...args);
  });
}
function changePlan(lane: typeof lanes[number], removed = false) {
  if (lane.cls === CortexClient) {
    vi.mocked(CortexClient.prototype.request).mockResolvedValue({ ok: true, data: removed ? [] : [{ id: "c", name: "C" }] } as never);
  } else {
    const technique = store.getTechnique("T1059")!;
    vi.spyOn(store, "getTechnique").mockReturnValue(removed ? undefined : { ...technique, name: "Changed reference", tactics: ["discovery", "execution"] });
  }
}
for (const lane of lanes) {
  it(`${lane.name}: completed replay returns known IDs without consulting mutable enrichment or discovery`, async () => {
    const first = await call(lane); expect(first.isError).not.toBe(true);
    vi.mocked(lane.cls.prototype.request).mockClear().mockRejectedValue(new Error("discovery unavailable"));
    vi.spyOn(store, "getTechnique").mockImplementation(() => { throw new Error("ATT&CK unavailable"); });
    const retry = await call(lane);
    expect(retry.isError).not.toBe(true);
    expect(JSON.stringify(retry)).toContain(expectedId(lane));
    expect(JSON.stringify(retry)).toContain('completed');
    expect(lane.cls.prototype.request).not.toHaveBeenCalled();
  });
  it.each([false, true])(`${lane.name}: partial plan drift blocks before any new mutation and reports retained IDs (removed: %s)`, async removed => {
    await failBeforeIntent();
    expect((await call(lane)).isError).toBe(true);
    const n = vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST").length;
    expect(n).toBe(1);
    changePlan(lane, removed);
    const retry = await call(lane);
    expect(retry.isError).toBe(true);
    expect(JSON.stringify(retry)).toContain("plan");
    expect(JSON.stringify(retry)).toContain(expectedId(lane));
    expect(JSON.stringify(retry)).not.toContain("private-ioc");
    expect(vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST")).toHaveLength(n);
  });
  it(`${lane.name}: immutable plan must be durable before the first POST`, async () => {
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    vi.mocked(open).mockImplementation(async (...args) => {
      const handle = await actual.open(...args);
      if (String(args[0]).endsWith("/plan.json")) vi.spyOn(handle, "sync").mockRejectedValue(new Error("plan fsync failed"));
      return handle;
    });
    expect((await call(lane)).isError).toBe(true);
    expect((await call(lane)).isError).toBe(true);
    expect(vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST")).toHaveLength(0);
  });
}
it("Cortex canonically resumes the original analyzer set when discovery order changes", async () => {
  await failBeforeIntent();
  expect((await call(lanes[2])).isError).toBe(true);
  const original = vi.mocked(CortexClient.prototype.request).getMockImplementation()!;
  vi.mocked(CortexClient.prototype.request).mockImplementation(async (...args) => args[0] === "GET"
    ? { ok: true, data: [{ id: "b", name: "B" }, { id: "a", name: "A" }] } as never : original(...args));
  expect((await call(lanes[2])).isError).not.toBe(true);
  expect(vi.mocked(CortexClient.prototype.request).mock.calls.filter(([m]) => m === "POST").map(([, path]) => path)).toEqual(["/api/analyzer/a/run", "/api/analyzer/b/run"]);
});
it("MISP resumes across midnight under the original event date", async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  try {
    vi.setSystemTime(new Date("2026-10-28T23:59:59Z"));
    await failBeforeIntent();
    expect((await call(lanes[0])).isError).toBe(true);
    vi.setSystemTime(new Date("2026-10-29T00:01:00Z"));
    expect((await call(lanes[0])).isError).not.toBe(true);
    const creates = vi.mocked(MispClient.prototype.request).mock.calls.filter(([, route]) => route === "/events/add");
    expect(creates).toHaveLength(1);
    expect(creates[0][2]).toMatchObject({ Event: { date: "2026-10-28" } });
  } finally { vi.useRealTimers(); }
});
it.each([false, true])("legacy receipts recover completed IDs and block partial replay without a recorded plan (complete: %s)", async complete => {
  expect((await call(lanes[0])).isError).not.toBe(true);
  const [id] = await readdir(state);
  const dir = join(state, id);
  const record = JSON.parse(await readFile(join(dir, "operation.json"), "utf8"));
  await writeFile(join(dir, "operation.json"), JSON.stringify({ fingerprint: record.fingerprint }));
  await unlink(join(dir, "plan.json")).catch(e => { if (e.code !== "ENOENT") throw e; });
  if (!complete) await unlink(join(dir, "complete.json"));
  vi.mocked(MispClient.prototype.request).mockClear();
  changePlan(lanes[0]);
  const retry = await call(lanes[0]);
  expect(retry.isError === true).toBe(!complete);
  expect(JSON.stringify(retry)).toContain("uuid-1");
  expect(MispClient.prototype.request).not.toHaveBeenCalled();
});

it.each(lanes)("$name: completed identity survives changed reference membership", async lane => {
  const parse = (result: unknown) => JSON.parse((result as { content: Array<{ text: string }> }).content[0].text);
  const first = parse(await call(lane));
  vi.mocked(lane.cls.prototype.request).mockClear();
  changePlan(lane, true);
  const retry = await call(lane);
  expect(retry.isError).not.toBe(true);
  const recovered = parse(retry);
  expect(recovered.operationId).toBe(first.operationId);
  expect(recovered.completed).toBe(true);
  if (lane.cls === MispClient) expect(recovered).toMatchObject({ eventId: first.eventId, eventUuid: first.eventUuid });
  else if (lane.cls === TheHiveClient) expect(recovered.caseId).toBe(first.caseId);
  else expect(recovered.jobs.map((j: { jobId: string }) => j.jobId)).toEqual(first.jobs.map((j: { jobId: string }) => j.jobId));
  expect(lane.cls.prototype.request).not.toHaveBeenCalled();
});
it.each(lanes.slice(0, 2))("$name: ATT&CK tactic ordering cannot change a partially completed plan", async lane => {
  const technique = store.getTechnique("T1059")!;
  const lookup = vi.spyOn(store, "getTechnique").mockReturnValue({ ...technique, tactics: ["execution", "discovery"] });
  await failBeforeIntent(3);
  expect((await call(lane)).isError).toBe(true);
  lookup.mockReturnValue({ ...technique, tactics: ["discovery", "execution"] });
  expect((await call(lane)).isError).not.toBe(true);
  const posts = vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST");
  expect(new Set(posts.map(([, path, body]) => JSON.stringify([path, body]))).size).toBe(posts.length);
});
it.each(lanes)("$name: changed planning data cannot replay an uncertain second step", async lane => {
  let n = 0;
  const request = vi.mocked(lane.cls.prototype.request).getMockImplementation()!;
  vi.mocked(lane.cls.prototype.request).mockImplementation(async (...args) => {
    if (args[0] === "POST" && ++n === 2) throw new Error("uncertain transport");
    return request(...args);
  });
  expect((await call(lane)).isError).toBe(true);
  changePlan(lane);
  const retry = await call(lane);
  expect(retry.isError).toBe(true);
  expect(JSON.stringify(retry)).toContain(expectedId(lane));
  expect(vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST")).toHaveLength(2);
});
it.each(lanes)("$name: missing immutable plan with existing intents cannot be replaced", async lane => {
  await failBeforeIntent();
  expect((await call(lane)).isError).toBe(true);
  const [id] = await readdir(state);
  await unlink(join(state, id, "plan.json"));
  changePlan(lane);
  const retry = await call(lane);
  expect(retry.isError).toBe(true);
  expect(JSON.stringify(retry)).toContain(expectedId(lane));
  expect(await readdir(join(state, id))).not.toContain("plan.json");
  expect(vi.mocked(lane.cls.prototype.request).mock.calls.filter(([m]) => m === "POST")).toHaveLength(1);
});
it.each(lanes)("$name: all recorded plan steps recover IDs after completion marker failure and reference drift", async lane => {
  const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  vi.mocked(open).mockImplementation((...args) => {
    if (String(args[0]).endsWith("/complete.json") && args[1] !== undefined && (Number(args[1]) & constants.O_CREAT)) throw Object.assign(new Error("completion disk failure"), { code: "ENOSPC" });
    return actual.open(...args);
  });
  expect((await call(lane)).isError).toBe(true);
  vi.mocked(open).mockImplementation(actual.open);
  vi.mocked(lane.cls.prototype.request).mockClear();
  changePlan(lane, true);
  const retry = await call(lane);
  expect(retry.isError).not.toBe(true);
  expect(JSON.stringify(retry)).toContain(expectedId(lane));
  expect(lane.cls.prototype.request).not.toHaveBeenCalled();
});
