import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
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
    return JSON.parse(await f.readFile("utf8"));
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
export async function operationClient(
  client: { operationScope: string; request<T>(method: string, path: string, body?: unknown): Promise<SocResponse<T>> },
  workflow: string, operationKey: string | undefined, payload: unknown,
): Promise<{ operationId: string; finish(): Promise<void>; request<T>(method: string, path: string, body?: unknown): Promise<SocResponse<T>> }> {
  if (!operationKey || !/^[A-Za-z0-9._~-]{1,128}$/.test(operationKey)) throw new OperationError("Actual writes require a stable operationKey (1-128 letters, digits, . _ ~ -). Reuse it for retries.");
  const operationId = hash([client.operationScope, workflow, operationKey]);
  const fail = (reason: string) => new OperationError(`Operation ${operationKey} (${operationId}): ${reason}. Inspect the private receipt and remote state with read tools. Do not retry with a new key or delete receipts to bypass this block.`);
  let path: string;
  try {
    const configuredRoot = process.env.MITRE_SOC_STATE_DIR;
    if (configuredRoot && !isAbsolute(configuredRoot)) throw new Error();
    const root = resolve(configuredRoot || join(homedir(), ".mitre-mcp", "operations"));
    await privateDirectory(root); path = join(root, operationId); await privateDirectory(path);
    const fingerprint = hash(payload);
    const created = await exclusive(join(path, "operation.json"), { fingerprint });
    if (!created && (await read(join(path, "operation.json")) as { fingerprint: string }).fingerprint !== fingerprint) throw fail("key payload mismatch");
  } catch (e) { if (e instanceof OperationError) throw e; throw fail("private operation state unavailable or unsafe"); }
  let completedSteps: number | undefined;
  try {
    completedSteps = (await read(join(path, "complete.json")) as { steps: number }).steps;
    if (!Number.isSafeInteger(completedSteps) || completedSteps! < 0) throw new Error();
  }
  catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw fail("invalid completion receipt"); }
  let step = 0;
  return { operationId, async finish() {
    if (completedSteps !== undefined && completedSteps !== step) throw fail("completed step plan mismatch");
    try {
      if (!await exclusive(join(path, "complete.json"), { steps: step })
        && (await read(join(path, "complete.json")) as { steps: number }).steps !== step) throw new Error();
    }
    catch { throw fail("completion receipt unavailable"); }
  }, async request<T>(method: string, route: string, body?: unknown): Promise<SocResponse<T>> {
    if (completedSteps !== undefined && step >= completedSteps) throw fail("completed step plan mismatch");
    const prefix = join(path, String(step++));
    const fingerprint = hash([method, route, body]);
    try {
      const owner = await exclusive(prefix + ".intent.json", { fingerprint });
      if (!owner) {
        if ((await read(prefix + ".intent.json") as { fingerprint: string }).fingerprint !== fingerprint) throw fail("step payload mismatch");
        const receipt = await read(prefix + ".done.json") as { fingerprint: string; data?: T };
        if (receipt.fingerprint !== fingerprint) throw fail("receipt mismatch");
        return { ok: true, data: receipt.data };
      }
      const response = await client.request<T>(method, route, body);
      if (!response.ok) throw fail("uncertain remote outcome");
      const data = ids(response.data);
      if ((route === "/events/add" && !(data?.Event as Record<string, unknown>)?.id)
        || (route === "/api/v1/case" && !data?._id)
        || (route.endsWith("/run") && !data?.id)) throw fail("uncertain remote identifier");
      if (!await exclusive(prefix + ".done.json", { fingerprint, data })) throw fail("unexpected completion receipt");
      // Both first run and replay use the same minimal ID projection.
      return { ok: true, data: data as T };
    } catch (e) { if (e instanceof OperationError) throw e; throw fail("uncertain or in-progress step outcome"); }
  } };
}
