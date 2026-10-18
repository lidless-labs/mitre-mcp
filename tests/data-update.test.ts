import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AttackDataStore } from "../src/data/index.js";
import { downloadAllMatrices } from "../src/data/loader.js";
import type { MitreConfig, StixBundle } from "../src/types.js";

function bundle(id: string): StixBundle {
  return { type: "bundle", id: `bundle--${id}`, objects: [{
    type: "attack-pattern", id: `attack-pattern--${id}`, name: id,
    created: "2026-01-01T00:00:00Z", modified: "2026-01-01T00:00:00Z",
    external_references: [{ source_name: "mitre-attack", external_id: id }],
  }] };
}
const dirs: string[] = [];
afterEach(() => {
  vi.unstubAllGlobals();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});
function config(): MitreConfig {
  const dataDir = mkdtempSync(join(tmpdir(), "mitre-update-"));
  dirs.push(dataDir);
  return { dataDir, matrices: ["enterprise"], updateInterval: 86400, soc: {} };
}

describe("shared dataset updates", () => {
  it("replaces removed records and retains the prior snapshot if parsing fails", () => {
    const store = new AttackDataStore(config());
    store.loadFromBundles(new Map([["enterprise", bundle("T1001")]]));
    expect(() => store.loadFromBundles(new Map([["enterprise", bundle("T1002")], ["mobile", { ...bundle("T1003"), objects: null! }]]))).toThrow();
    expect(store.getTechnique("T1001")).toBeDefined();
    store.loadFromBundles(new Map([["enterprise", bundle("T1002")]]));
    expect(store.getTechnique("T1001")).toBeUndefined();
    expect(store.getAllTechniques().map((t) => t.id)).toEqual(["T1002"]);
  });

  it("shares in-flight updates and serves the old snapshot until replacement", async () => {
    const cfg = config();
    const store = new AttackDataStore(cfg);
    store.loadFromBundles(new Map([["enterprise", bundle("T1001")]]));
    let release!: (response: Response) => void;
    const fetcher = vi.fn(() => new Promise<Response>((resolve) => { release = resolve; }));
    vi.stubGlobal("fetch", fetcher);
    const a = store.refresh();
    const b = store.refresh();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(store.getTechnique("T1001")).toBeDefined();
    release(Response.json(bundle("T1002")));
    await Promise.all([a, b]);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(store.getTechnique("T1001")).toBeUndefined();
    expect(store.getTechnique("T1002")).toBeDefined();
    expect(JSON.parse(readFileSync(join(cfg.dataDir, "enterprise-attack.json"), "utf8"))).toEqual(bundle("T1002"));
  });

  it("leaves all cached matrices intact when a later download fails", async () => {
    const cfg = config();
    const old = JSON.stringify(bundle("T1001"));
    writeFileSync(join(cfg.dataDir, "enterprise-attack.json"), old);
    writeFileSync(join(cfg.dataDir, "metadata.json"), "{}");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(Response.json(bundle("T1002"))).mockResolvedValueOnce(new Response("unavailable", { status: 503 })));
    await expect(downloadAllMatrices(cfg.dataDir, ["enterprise", "mobile"])).rejects.toThrow(/503/);
    expect(readFileSync(join(cfg.dataDir, "enterprise-attack.json"), "utf8")).toBe(old);
    expect(readFileSync(join(cfg.dataDir, "metadata.json"), "utf8")).toBe("{}");
  });
});
