import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, rmSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import type { MatrixType, StixBundle } from "../types.js";

const STIX_URLS: Record<MatrixType, string> = {
  enterprise:
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
  mobile:
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
  ics: "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
};

interface CacheMetadata {
  lastUpdated: string;
  matrices: string[];
}

function getCachePath(dataDir: string, matrix: MatrixType): string {
  return join(dataDir, `${matrix}-attack.json`);
}

function getMetadataPath(dataDir: string): string {
  return join(dataDir, "metadata.json");
}

export function ensureDataDir(dataDir: string): void {
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }
}

export function isCacheStale(
  dataDir: string,
  updateInterval: number,
): boolean {
  const metaPath = getMetadataPath(dataDir);
  if (!existsSync(metaPath)) return true;

  try {
    const meta: CacheMetadata = JSON.parse(readFileSync(metaPath, "utf-8"));
    const lastUpdated = new Date(meta.lastUpdated).getTime();
    const now = Date.now();
    return now - lastUpdated > updateInterval * 1000;
  } catch {
    return true;
  }
}

export function hasCachedData(
  dataDir: string,
  matrices: MatrixType[],
): boolean {
  return matrices.every((m) => existsSync(getCachePath(dataDir, m)));
}

async function fetchMatrix(matrix: MatrixType): Promise<StixBundle> {
  const response = await fetch(STIX_URLS[matrix]);
  if (!response.ok) {
    throw new Error(`Failed to download ${matrix} ATT&CK data: ${response.status} ${response.statusText}`);
  }
  const data = (await response.json()) as StixBundle;
  if (data.type !== "bundle" || !Array.isArray(data.objects)) {
    throw new Error(`Invalid ${matrix} ATT&CK bundle`);
  }
  return data;
}

// Stage complete files beside their destination for atomic same-filesystem
// rename. No live file is truncated, and no asynchronous read can interleave
// with publication of the complete set within this process.
function publish(dataDir: string, files: [string, string][]): void {
  ensureDataDir(dataDir);
  const staged: [string, string][] = [];
  try {
    for (const [destination, contents] of files) {
      const temporary = `${destination}.${randomUUID()}.tmp`;
      staged.push([temporary, destination]);
      writeFileSync(temporary, contents, { flag: "wx", mode: 0o600 });
    }
    for (const [temporary, destination] of staged) renameSync(temporary, destination);
  } finally {
    for (const [temporary] of staged) rmSync(temporary, { force: true });
  }
}

export async function downloadMatrix(dataDir: string, matrix: MatrixType): Promise<StixBundle> {
  const data = await fetchMatrix(matrix);
  publish(dataDir, [[getCachePath(dataDir, matrix), JSON.stringify(data)]]);
  return data;
}

export async function downloadAllMatrices(
  dataDir: string,
  matrices: MatrixType[],
): Promise<Map<MatrixType, StixBundle>> {
  const bundles = new Map<MatrixType, StixBundle>();
  // Finish every download before touching the live cache.
  for (const matrix of matrices) bundles.set(matrix, await fetchMatrix(matrix));
  const meta: CacheMetadata = {
    lastUpdated: new Date().toISOString(),
    matrices: matrices as string[],
  };
  publish(dataDir, [
    ...[...bundles].map(([matrix, bundle]): [string, string] => [getCachePath(dataDir, matrix), JSON.stringify(bundle)]),
    [getMetadataPath(dataDir), JSON.stringify(meta, null, 2)],
  ]);
  return bundles;
}

export function loadCachedBundle(
  dataDir: string,
  matrix: MatrixType,
): StixBundle | null {
  const cachePath = getCachePath(dataDir, matrix);
  if (!existsSync(cachePath)) return null;

  try {
    return JSON.parse(readFileSync(cachePath, "utf-8")) as StixBundle;
  } catch {
    return null;
  }
}

export function loadCachedBundles(
  dataDir: string,
  matrices: MatrixType[],
): Map<MatrixType, StixBundle> | null {
  const bundles = new Map<MatrixType, StixBundle>();

  for (const matrix of matrices) {
    const bundle = loadCachedBundle(dataDir, matrix);
    if (!bundle) return null;
    bundles.set(matrix, bundle);
  }

  return bundles;
}

export function getCacheAge(dataDir: string): number | null {
  const metaPath = getMetadataPath(dataDir);
  if (!existsSync(metaPath)) return null;

  try {
    const meta: CacheMetadata = JSON.parse(readFileSync(metaPath, "utf-8"));
    return Date.now() - new Date(meta.lastUpdated).getTime();
  } catch {
    return null;
  }
}

export function getLastUpdated(dataDir: string): string | null {
  const metaPath = getMetadataPath(dataDir);
  if (!existsSync(metaPath)) return null;

  try {
    const meta: CacheMetadata = JSON.parse(readFileSync(metaPath, "utf-8"));
    return meta.lastUpdated;
  } catch {
    return null;
  }
}
