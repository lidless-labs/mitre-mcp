import { describe, it, expect, vi } from "vitest";
import { UsageError, parseArgs, run, type CliDeps } from "../src/cli.js";
import type { AttackDataStore } from "../src/data/index.js";

function capture(overrides: Record<string, unknown>, serve = vi.fn().mockResolvedValue(undefined)) {
  const out: string[] = [];
  const err: string[] = [];
  const store = {
    initialize: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  } as unknown as AttackDataStore;
  const deps: CliDeps = {
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    makeStore: () => store,
    serve,
  };
  return { out, err, deps, serve, store };
}

describe("parseArgs", () => {
  it("routes lookups, flags, and search --type", () => {
    expect(parseArgs(["technique", "T1059"])).toEqual({ kind: "run", command: "technique", value: "T1059", type: undefined, json: false });
    expect(parseArgs(["tactics"])).toEqual({ kind: "run", command: "tactics", value: undefined, type: undefined, json: false });
    expect(parseArgs(["search", "powershell", "--type", "group"])).toEqual({ kind: "run", command: "search", value: "powershell", type: "group", json: false });
    expect(parseArgs(["stats", "--json"])).toMatchObject({ command: "stats", json: true });
    expect(parseArgs(["--version"])).toEqual({ kind: "version" });
    expect(parseArgs(["mcp"])).toEqual({ kind: "mcp" });
    expect(parseArgs([])).toEqual({ kind: "help" });
  });

  it("rejects bad input with UsageError", () => {
    expect(() => parseArgs(["bogus"])).toThrow(UsageError);
    expect(() => parseArgs(["technique"])).toThrow(UsageError);
    expect(() => parseArgs(["tactics", "extra"])).toThrow(UsageError);
    expect(() => parseArgs(["search", "x", "--type"])).toThrow(UsageError);
  });
});

describe("run", () => {
  it("prints a found technique and exits 0", async () => {
    const { out, deps } = capture({ getTechnique: vi.fn().mockReturnValue({ id: "T1059", name: "Command and Scripting Interpreter" }) });
    expect(await run(["technique", "T1059"], deps)).toBe(0);
    expect(out.join("\n")).toContain("T1059");
    expect(out.join("\n")).toContain("Command and Scripting Interpreter");
  });

  it("exits 1 when a lookup returns nothing", async () => {
    const { err, deps } = capture({ getTechnique: vi.fn().mockReturnValue(undefined) });
    expect(await run(["technique", "T9999"], deps)).toBe(1);
    expect(err.join("\n")).toContain("not found");
  });

  it("routes search by --type and lists results", async () => {
    const searchGroups = vi.fn().mockReturnValue([{ id: "G0016", name: "APT29" }]);
    const { out, deps, store } = capture({ searchGroups });
    expect(await run(["search", "cozy", "--type", "group"], deps)).toBe(0);
    expect(searchGroups).toHaveBeenCalledWith({ query: "cozy" });
    expect(out.join("\n")).toContain("G0016");
  });

  it("emits raw JSON with --json", async () => {
    const stats = { techniques: 200, groups: 130, software: 600 };
    const { out, deps } = capture({ getStats: vi.fn().mockReturnValue(stats) });
    expect(await run(["stats", "--json"], deps)).toBe(0);
    expect(JSON.parse(out.join("\n"))).toEqual(stats);
  });

  it("returns exit 1 when the store fails", async () => {
    const { err, deps } = capture({ getAllTactics: vi.fn(() => { throw new Error("ATT&CK data not loaded"); }) });
    expect(await run(["tactics"], deps)).toBe(1);
    expect(err.join("\n")).toContain("not loaded");
  });

  it("returns exit 2 and prints help on usage error", async () => {
    const { err, deps } = capture({});
    expect(await run(["bogus"], deps)).toBe(2);
    expect(err.join("\n")).toContain("Usage:");
  });

  it("delegates mcp to serve()", async () => {
    const { deps, serve } = capture({});
    expect(await run(["mcp"], deps)).toBe(0);
    expect(serve).toHaveBeenCalledOnce();
  });
});
