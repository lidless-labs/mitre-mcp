// Shared helpers for SOC integration tools: ID validation, safe path
// encoding, and the write-confirmation guard.

// Strict allow-list for IDs that get interpolated into SOC API request paths
// or query strings. Accepts the formats actually used by these platforms:
// numeric IDs, TheHive/MISP object IDs, UUIDs, and short slug-like tokens.
const SAFE_ID_PATTERN = /^[A-Za-z0-9._~-]+$/;

/**
 * Validate that an untrusted (LLM-supplied) identifier is safe to splice into
 * an API route, then return it percent-encoded. Throws on anything containing
 * path separators, query metacharacters, or whitespace so a caller can never
 * pivot to a different API route within the trusted SOC host.
 */
export function safePathSegment(value: string, label = "id"): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Invalid ${label}: must be a non-empty string`);
  }
  if (value.length > 256) {
    throw new Error(`Invalid ${label}: too long`);
  }
  if (!SAFE_ID_PATTERN.test(value)) {
    throw new Error(
      `Invalid ${label}: must match ${SAFE_ID_PATTERN.source} (got "${value}")`,
    );
  }
  return encodeURIComponent(value);
}

/**
 * Validate a free-form value that will be placed in a URL path or query string
 * but is not constrained to the strict ID pattern (e.g. an enum already
 * narrowed by the schema). Only enforces percent-encoding, not the allow-list.
 */
export function encodeSegment(value: string): string {
  return encodeURIComponent(value);
}

/**
 * Returns true when state-changing SOC tools are permitted to execute.
 *
 * Two opt-in paths, mirroring the existing `addTags` default-false guard:
 *   1. Per-call: the tool's `confirm` argument is explicitly `true`.
 *   2. Global:   the `MITRE_SOC_ALLOW_WRITES` env var is set to a truthy value,
 *                which pre-authorizes writes without a per-call `confirm`.
 *
 * Without either, write/execute tools run in dry-run mode and report what they
 * WOULD have done instead of mutating the SOC platform.
 */
export function writesAllowed(confirm?: boolean): boolean {
  if (confirm === true) return true;
  const env = (process.env.MITRE_SOC_ALLOW_WRITES || "").toLowerCase();
  return env === "1" || env === "true" || env === "yes";
}
