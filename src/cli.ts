import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { AttackDataStore } from "./data/index.js";
import { loadConfig } from "./config.js";
import { serve } from "./index.js";
import pkg from "../package.json";

export class UsageError extends Error {}

interface CommandSpec {
  arg?: "id" | "query";
  run: (store: AttackDataStore, args: { value?: string; type?: string }) => unknown;
}

function searchByType(store: AttackDataStore, query: string, type?: string): unknown {
  switch (type) {
    case "group":
    case "groups":
      return store.searchGroups({ query });
    case "software":
      return store.searchSoftware({ query });
    case "mitigation":
    case "mitigations":
      return store.searchMitigations(query);
    case "campaign":
    case "campaigns":
      return store.searchCampaigns({ query });
    case undefined:
    case "technique":
    case "techniques":
      return store.searchTechniques({ query });
    default:
      throw new UsageError("--type must be one of: technique, group, software, mitigation, campaign");
  }
}

// Only read/lookup methods of AttackDataStore (a local read-only data cache) are
// reachable here, so the CLI cannot mutate or refresh the underlying data.
const COMMANDS: Record<string, CommandSpec> = {
  technique: { arg: "id", run: (s, a) => s.getTechnique(a.value as string) },
  tactic: { arg: "id", run: (s, a) => s.getTactic(a.value as string) },
  tactics: { run: (s) => s.getAllTactics() },
  group: { arg: "id", run: (s, a) => s.getGroup(a.value as string) },
  software: { arg: "id", run: (s, a) => s.getSoftware(a.value as string) },
  mitigation: { arg: "id", run: (s, a) => s.getMitigation(a.value as string) },
  campaign: { arg: "id", run: (s, a) => s.getCampaign(a.value as string) },
  campaigns: { run: (s) => s.getAllCampaigns() },
  datasource: { arg: "id", run: (s, a) => s.getDataSource(a.value as string) },
  "mitigations-for": { arg: "id", run: (s, a) => s.getMitigationsForTechnique(a.value as string) },
  search: { arg: "query", run: (s, a) => searchByType(s, a.value as string, a.type) },
  stats: { run: (s) => s.getStats() },
};

export const HELP = `attack - read-only MITRE ATT&CK lookup (shares the mitre-mcp data core)

Usage:
  attack <command> [options]

Lookups:
  technique <id>          One technique by ATT&CK id (e.g. T1059)
  tactic <id>             One tactic
  tactics                 List all tactics
  group <id|name>         One group / threat actor (e.g. G0016 or APT29)
  software <id|name>      One software / tool
  mitigation <id>         One mitigation
  campaign <id|name>      One campaign
  campaigns               List all campaigns
  datasource <id|name>    One data source
  mitigations-for <id>    Mitigations mapped to a technique
  search <query>          Search (--type technique|group|software|mitigation|campaign; default technique)
  stats                   ATT&CK data counts + version

Server:
  mcp                     Start the MCP server over stdio
  help                    Show this help

Global options:
  --json                  Emit raw JSON instead of the summary view
  --version, -v           Print version
  --help, -h              Show help

Environment:
  ATTACK_DATA_DIR         Override the ATT&CK data cache directory

This is a read-only search tool. Data refresh and SOC correlation stay in the MCP server.`;

function takeFlag(args: string[], name: string): boolean {
  const i = args.indexOf(name);
  if (i === -1) return false;
  args.splice(i, 1);
  return true;
}

function takeOption(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  if (i === -1) return undefined;
  const v = args[i + 1];
  if (v === undefined || v.startsWith("--")) throw new UsageError(`${name} requires a value`);
  args.splice(i, 2);
  return v;
}

function reqStr(v: string | undefined, name: string): string {
  if (v === undefined || v === "") throw new UsageError(`${name} is required`);
  return v;
}

function ensureNoExtra(args: string[]): void {
  if (args.length) throw new UsageError(`Unexpected arguments: ${args.join(" ")}`);
}

export type Parsed =
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "mcp" }
  | { kind: "run"; command: string; value?: string; type?: string; json: boolean };

export function parseArgs(argv: string[]): Parsed {
  const args = [...argv];
  if (args.includes("-h") || args.includes("--help")) return { kind: "help" };
  if (args.includes("-v") || args.includes("--version")) return { kind: "version" };
  const json = takeFlag(args, "--json");
  const type = takeOption(args, "--type");

  const cmd = args.shift();
  if (!cmd || cmd === "help") return { kind: "help" };
  if (cmd === "mcp") return { kind: "mcp" };

  const spec = COMMANDS[cmd];
  if (!spec) throw new UsageError(`unknown command: ${cmd}`);

  let value: string | undefined;
  if (spec.arg) value = reqStr(args.shift(), spec.arg);
  ensureNoExtra(args);
  return { kind: "run", command: cmd, value, type, json };
}

function summarize(item: unknown): string {
  if (item && typeof item === "object") {
    const o = item as Record<string, unknown>;
    const keys = ["id", "attackId", "name", "shortName", "type"].filter((k) => k in o);
    if (keys.length) return keys.map((k) => `${k}=${String(o[k])}`).join("  ");
    return JSON.stringify(o);
  }
  return String(item);
}

function render(data: unknown): string {
  if (Array.isArray(data)) {
    return [`${data.length} result(s):`, ...data.map((it) => `  ${summarize(it)}`)].join("\n");
  }
  return JSON.stringify(data, null, 2);
}

export interface CliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  makeStore: () => AttackDataStore;
  serve: () => Promise<void>;
}

export async function run(argv: string[], deps: CliDeps): Promise<number> {
  let parsed: Parsed;
  try {
    parsed = parseArgs(argv);
  } catch (error) {
    deps.err(error instanceof Error ? error.message : String(error));
    deps.err("");
    deps.err(HELP);
    return 2;
  }

  if (parsed.kind === "help") {
    deps.out(HELP);
    return 0;
  }
  if (parsed.kind === "version") {
    deps.out(pkg.version);
    return 0;
  }
  if (parsed.kind === "mcp") {
    await deps.serve();
    return 0;
  }

  try {
    const store = deps.makeStore();
    await store.initialize();
    const spec = COMMANDS[parsed.command];
    const result = spec.run(store, { value: parsed.value, type: parsed.type });
    if (result === undefined || result === null) {
      deps.err(`${parsed.command}: not found`);
      return 1;
    }
    deps.out(parsed.json ? JSON.stringify(result) : render(result));
    return 0;
  } catch (error) {
    deps.err(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

// True when this module is the process entrypoint (symlink-safe).
const isEntrypoint = (() => {
  const arg = process.argv[1];
  if (typeof arg !== "string") return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(arg)).href;
  } catch {
    return false;
  }
})();

if (isEntrypoint) {
  run(process.argv.slice(2), {
    out: (s) => process.stdout.write(`${s}\n`),
    err: (s) => process.stderr.write(`${s}\n`),
    makeStore: () => new AttackDataStore(loadConfig()),
    serve,
  })
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    });
}
