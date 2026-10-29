import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { SocResponse } from "./client.js";

const hash = (data: unknown) => createHash("sha256").update(JSON.stringify(data)).digest("hex");
export class OperationError extends Error {}

// The operator owns this directory and its ancestors. Other processes running
// as the same OS user are trusted. Never reclaim an intent based on age/PID.
async function privateDirectory(path: string): Promise<void> {
  const parent = dirname(path);
  if (parent !== path) {
    try { const s = await lstat(parent); if (!s.isDirectory() || s.isSymbolicLink()) throw new Error(); }
    catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      await privateDirectory(parent);
    }
  }
  try { await mkdir(path, { mode: 0o700 }); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e; }
  const s = await lstat(path);
  if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== process.getuid?.() || (s.mode & 0o077)) throw new Error();
  // Check every existing ancestor for symlinks, including operator-owned paths.
  for (let p = parent; dirname(p) !== p; p = dirname(p)) {
    const stat = await lstat(p);
    const trustedOwner = stat.uid === 0 || stat.uid === process.getuid?.();
    const writable = stat.mode & 0o022;
    const sticky = stat.mode & 0o1000;
    if (!stat.isDirectory() || stat.isSymbolicLink() || !trustedOwner || (writable && !sticky)) throw new Error();
  }
  // Persist every directory entry up to the filesystem root. An existing
  // entry may have just been created by a concurrent same-user mkdir winner,
  // or survived a prior failed sync. Receipt fsync alone cannot publish it.
  for (let p = path; ; p = dirname(p)) {
    await syncDirectory(dirname(p));
    if (dirname(p) === p) break;
  }
}
async function syncDirectory(path: string): Promise<void> { const f = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW); try { await f.sync(); } finally { await f.close(); } }
async function read(path: string): Promise<unknown> {
  const f = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const s = await f.stat();
    if (!s.isFile() || s.uid !== process.getuid?.() || (s.mode & 0o077) || s.size > 16_384) throw new Error();
    const data = JSON.parse(await f.readFile("utf8"));
    // An earlier writer may have failed between writing and syncing this file.
    await f.sync();
    await syncDirectory(dirname(path));
    return data;
  } finally { await f.close(); }
}
// Exclusive files are immutable. A crash during creation leaves a receipt that
// fails closed, rather than a partially written record that could be replayed.
async function exclusive(path: string, data: unknown): Promise<boolean> {
  let f;
  try { f = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (e) { if ((e as NodeJS.ErrnoException).code === "EEXIST") return false; throw e; }
  try { await f.writeFile(JSON.stringify(data)); await f.sync(); } finally { await f.close(); }
  await syncDirectory(dirname(path)); return true;
}
// Retain only IDs needed by subsequent steps. Never persist response bodies,
// caller text, IOCs, credentials, or the final result.
function ids(data: unknown): Record<string, unknown> | undefined {
  if (!data || typeof data !== "object") return undefined;
  const source = data as Record<string, unknown>, result: Record<string, unknown> = {};
  for (const key of ["id", "_id", "uuid"]) if (typeof source[key] === "string" && /^[A-Za-z0-9._~-]{1,256}$/.test(source[key] as string)) result[key] = source[key];
  if (source.Event) result.Event = ids(source.Event);
  return result;
}
export interface OperationMutation { route: string; body?: unknown }
interface KnownStep { step: number; data?: ReturnType<typeof ids>; targetId?: string }
const MAX_STEPS = 1000;
const validHash = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

export async function operationClient(
  client: { operationScope: string; request<T>(method: string, path: string, body?: unknown): Promise<SocResponse<T>> },
  workflow: string, operationKey: string | undefined, payload: unknown,
) {
  if (!operationKey || !/^[A-Za-z0-9._~-]{1,128}$/.test(operationKey)) throw new OperationError("Actual writes require a stable operationKey (1-128 letters, digits, . _ ~ -). Reuse it for retries.");
  const operationId = hash([client.operationScope, workflow, operationKey]);
  const knownSteps: KnownStep[] = [];
  const fail = (reason: string) => new OperationError(`Operation ${operationKey} (${operationId}): ${reason}. Known completed step IDs: ${JSON.stringify(knownSteps).slice(0, 12_000)}. Full IDs remain in the private receipts. Inspect the private receipt and remote state with read tools. Do not retry with a new key or delete receipts to bypass this block.`);
  let path: string;
  let record: { fingerprint: string; version?: number; date?: string };
  try {
    const configuredRoot = process.env.MITRE_SOC_STATE_DIR;
    if (configuredRoot && !isAbsolute(configuredRoot)) throw new Error();
    const root = resolve(configuredRoot || join(homedir(), ".mitre-mcp", "operations"));
    await privateDirectory(root); path = join(root, operationId); await privateDirectory(path);
    const fingerprint = hash(payload);
    await exclusive(join(path, "operation.json"), { fingerprint, version: 2, date: new Date().toISOString().split("T")[0] });
    record = await read(join(path, "operation.json")) as typeof record;
    if (record.fingerprint !== fingerprint) throw fail("key payload mismatch");
  } catch (e) { if (e instanceof OperationError) throw e; throw fail("private operation state unavailable or unsafe"); }
  let completedSteps: number | undefined;
  try {
    completedSteps = (await read(join(path, "complete.json")) as { steps: number }).steps;
    if (!Number.isSafeInteger(completedSteps) || completedSteps! < 0 || completedSteps! > MAX_STEPS) throw new Error();
  }
  catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw fail("invalid completion receipt"); }
  let intentSteps: number[] = [];
  try {
    const entries = await readdir(path);
    intentSteps = entries.filter(name => /^(0|[1-9][0-9]*)\.intent\.json$/.test(name)).map(name => Number(name.split(".")[0]));
    if (intentSteps.length > MAX_STEPS || intentSteps.some(step => !Number.isSafeInteger(step) || step >= MAX_STEPS)) throw new Error();
    const steps = entries.filter(name => /^(0|[1-9][0-9]*)\.done\.json$/.test(name)).map(name => Number(name.split(".")[0])).sort((a, b) => a - b);
    if (steps.length > MAX_STEPS) throw new Error();
    for (const step of steps) {
      if (!Number.isSafeInteger(step) || step >= MAX_STEPS) throw new Error();
      const prefix = join(path, String(step));
      const intent = await read(prefix + ".intent.json") as { fingerprint: string };
      const receipt = await read(prefix + ".done.json") as { fingerprint: string; data?: unknown; targetId?: string };
      if (!validHash(intent.fingerprint) || receipt.fingerprint !== intent.fingerprint
        || JSON.stringify(receipt.data) !== JSON.stringify(ids(receipt.data))
        || (receipt.targetId !== undefined && !/^[A-Za-z0-9._~-]{1,256}$/.test(receipt.targetId))) throw new Error();
      knownSteps.push({ step, data: ids(receipt.data), targetId: receipt.targetId });
    }
    if (completedSteps !== undefined && (knownSteps.length !== completedSteps || intentSteps.length !== completedSteps || knownSteps.some((s, i) => s.step !== i))) throw new Error();
  } catch { throw fail("invalid step receipts"); }
  // Older journals have sufficient receipts to report a completed operation,
  // but cannot authorize a partial retry under a plan they never recorded.
  if (completedSteps === undefined && (record.version !== 2 || !record.date || !/^\d{4}-\d{2}-\d{2}$/.test(record.date))) throw fail("blocked recovery: no immutable plan metadata");
  if (completedSteps === undefined) {
    let plan: { fingerprint: string; steps: number } | undefined;
    try {
      plan = await read(join(path, "plan.json")) as typeof plan;
      if (!plan || !validHash(plan.fingerprint) || !Number.isSafeInteger(plan.steps) || plan.steps < 0 || plan.steps > MAX_STEPS
        || intentSteps.some(step => step >= plan!.steps)) throw new Error();
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw fail("immutable plan unavailable or unsafe");
      if (intentSteps.length) throw fail("blocked recovery: immutable plan missing for recorded intents");
    }
    // A crash or disk-full error may prevent the final marker. The sealed plan
    // and a successful receipt for every planned intent already prove the
    // original sequence finished, without consulting mutable enrichment.
    if (plan && knownSteps.length === plan.steps && knownSteps.every((s, i) => s.step === i)) completedSteps = plan.steps;
  }
  let started = false;
  return { operationId, date: record.date,
    error: (error?: unknown) => error instanceof OperationError ? error : fail("blocked recovery: immutable plan or local processing unavailable"),
    completed: completedSteps === undefined ? undefined : { operationId, completed: true, knownSteps },
    async run(
      mutations: OperationMutation[],
      parentSegment?: (first: Record<string, unknown>) => string,
    ): Promise<Array<SocResponse<Record<string, unknown>>>> {
      if (started || completedSteps !== undefined) throw fail("operation already completed or running");
      started = true;
      // Only hashes and a bounded count reach disk. The caller's raw payload,
      // request bodies and ATT&CK enrichment remain in memory.
      const plan = { fingerprint: hash(mutations), steps: mutations.length };
      try {
        if (mutations.length > MAX_STEPS) throw new Error();
        await exclusive(join(path, "plan.json"), plan);
        const recorded = await read(join(path, "plan.json")) as typeof plan;
        if (recorded.fingerprint !== plan.fingerprint || recorded.steps !== plan.steps) throw fail("blocked recovery: immutable step plan changed");
      } catch (e) { if (e instanceof OperationError) throw e; throw fail("immutable plan unavailable or unsafe"); }
      const responses: Array<SocResponse<Record<string, unknown>>> = [];
      for (const [step, mutation] of mutations.entries()) {
        let route = mutation.route;
        if (route.includes("{id}")) {
          // Tool binders use util.safePathSegment on the retained parent ID.
          if (!parentSegment || !responses[0]?.data) throw fail("invalid parent identifier");
          route = route.replace("{id}", parentSegment(responses[0].data));
        }
        const prefix = join(path, String(step));
        const fingerprint = hash(["POST", route, mutation.body]);
        try {
          const owner = await exclusive(prefix + ".intent.json", { fingerprint });
          if (!owner) {
            if ((await read(prefix + ".intent.json") as { fingerprint: string }).fingerprint !== fingerprint) throw fail("step payload mismatch");
            const receipt = await read(prefix + ".done.json") as { fingerprint: string; data?: Record<string, unknown> };
            if (receipt.fingerprint !== fingerprint) throw fail("receipt mismatch");
            responses.push({ ok: true, data: receipt.data });
            continue;
          }
          const response = await client.request("POST", route, mutation.body);
          if (!response.ok) throw fail("uncertain remote outcome");
          const data = ids(response.data);
          if ((route === "/events/add" && !(data?.Event as Record<string, unknown>)?.id)
            || (route === "/api/v1/case" && !data?._id)
            || (route.endsWith("/run") && !data?.id)) throw fail("uncertain remote identifier");
          const targetId = route.match(/^\/api\/analyzer\/([A-Za-z0-9._~-]{1,256})\/run$/)?.[1];
          if (!await exclusive(prefix + ".done.json", { fingerprint, data, targetId })) throw fail("unexpected completion receipt");
          knownSteps.push({ step, data, targetId });
          // Both first run and replay use the same minimal ID projection.
          responses.push({ ok: true, data });
        } catch (e) { if (e instanceof OperationError) throw e; throw fail("uncertain or in-progress step outcome"); }
      }
      try {
        if (!await exclusive(join(path, "complete.json"), { steps: mutations.length })
          && (await read(join(path, "complete.json")) as { steps: number }).steps !== mutations.length) throw new Error();
      } catch { throw fail("completion receipt unavailable"); }
      return responses;
    },
  };
}
