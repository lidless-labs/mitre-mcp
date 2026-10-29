import { createHash } from "node:crypto";
import { Agent } from "undici";
import { socFailure, socRequestError } from "./util.js";
import type { SocConfig } from "../types.js";

// Credential rotation must not turn a retry into a new remote operation.
function targetScope(url: string): string {
  const target = new URL(url);
  target.username = "";
  target.password = "";
  target.hash = "";
  return createHash("sha256").update(target.href.replace(/\/$/, "")).digest("hex");
}

export interface SocResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
  status?: number;
}

const MAX_RESPONSE_BYTES = 1_048_576;
const REQUEST_DEADLINE_MS = 30_000;

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    if (signal.aborted) { void promise.catch(() => undefined); reject(signal.reason); return; }
    signal.addEventListener("abort", abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
function cancelBody(body: ReadableStream<Uint8Array> | null): void {
  // Error/cancel diagnostics are untrusted. Cancellation must not hold the
  // response path open when a remote stream refuses to finish cleanup.
  try { void body?.cancel().catch(() => undefined); } catch { /* already locked */ }
}

// Keep the deadline and per-request TLS dispatcher alive through body EOF.
// Cap bytes before buffering or parsing, including the Wazuh auth response.
async function socFetch(
  url: string,
  options: RequestInit & { rejectUnauthorized?: boolean } = {},
): Promise<Response> {
  const { rejectUnauthorized, ...fetchOpts } = options;
  const signal = options.signal || AbortSignal.timeout(REQUEST_DEADLINE_MS);
  const agent = rejectUnauthorized === false ? new Agent({ connect: { rejectUnauthorized: false } }) : undefined;
  let response: Response | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    response = await abortable(fetch(url, { ...fetchOpts, signal, ...(agent ? { dispatcher: agent } : {}) } as RequestInit), signal);
    if (!response.ok) { cancelBody(response.body); return response; }
    const declared = response.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) throw new Error("SOC response size limit exceeded.");
    reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    if (reader) for (;;) {
      const { value, done } = await abortable(reader.read(), signal);
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_RESPONSE_BYTES) throw new Error("SOC response size limit exceeded.");
      chunks.push(value);
    }
    signal.throwIfAborted();
    return new Response(bytes ? Buffer.concat(chunks, bytes) : null, { status: response.status, headers: response.headers });
  } catch (error) {
    if (reader) void reader.cancel().catch(() => undefined);
    else if (response) cancelBody(response.body);
    throw error;
  } finally {
    reader?.releaseLock();
    if (agent) void agent.close().catch(() => undefined);
  }
}

// Error bodies and reason phrases can contain credentials, proxy diagnostics,
// or attacker instructions. Discard them and expose only the HTTP status.
async function parseResponseBody<T>(
  response: Response,
): Promise<{ data?: T; error?: string }> {
  if (!response.ok) {
    cancelBody(response.body);
    return { error: socFailure(response) };
  }
  const raw = await response.text();
  if (raw.length === 0) return { data: undefined };
  try {
    // Some SOC servers omit the content-type header on valid JSON responses.
    return { data: JSON.parse(raw) as T };
  } catch {
    return { error: `Invalid SOC response (HTTP ${response.status}).` };
  }
}

// Wazuh client
export class WazuhClient {
  readonly operationScope: string;
  private baseUrl: string;
  private username: string;
  private password: string;
  private verifySsl: boolean;
  private token: string | null = null;
  private tokenExpiry = 0;

  constructor(config: NonNullable<SocConfig["wazuh"]>) {
    this.operationScope = targetScope(config.url);
    this.baseUrl = config.url.replace(/\/$/, "");
    this.username = config.username;
    this.password = config.password;
    this.verifySsl = config.verifySsl;
  }

  private async authenticate(signal: AbortSignal): Promise<string> {
    if (this.token && Date.now() < this.tokenExpiry) {
      return this.token;
    }

    const response = await socFetch(
      `${this.baseUrl}/security/user/authenticate`,
      {
        method: "POST",
        signal,
        headers: {
          Authorization: `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`,
        },
        rejectUnauthorized: this.verifySsl,
      },
    );

    if (!response.ok) {
      throw new Error(socFailure(response));
    }

    const body = (await response.json()) as { data?: { token?: string } };
    if (!body.data?.token) {
      throw new Error("Wazuh auth response missing token");
    }

    this.token = body.data.token;
    // Wazuh tokens last 15 minutes, refresh at 12
    this.tokenExpiry = Date.now() + 12 * 60 * 1000;
    return this.token;
  }

  async request<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<SocResponse<T>> {
    try {
      const signal = AbortSignal.timeout(REQUEST_DEADLINE_MS);
      const token = await this.authenticate(signal);
      const url = `${this.baseUrl}${path}`;

      const response = await socFetch(url, {
        method,
        signal,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
        rejectUnauthorized: this.verifySsl,
      });

      const { data, error: parseError } = await parseResponseBody<T>(response);
      return {
        ok: response.ok && !parseError,
        data,
        error: parseError,
        status: response.status,
      };
    } catch (error) {
      return {
        ok: false,
        error: socRequestError(error),
      };
    }
  }
}

// TheHive client
export class TheHiveClient {
  readonly operationScope: string;
  private baseUrl: string;
  private apiKey: string;

  constructor(config: NonNullable<SocConfig["thehive"]>) {
    this.operationScope = targetScope(config.url);
    this.baseUrl = config.url.replace(/\/$/, "");
    this.apiKey = config.apiKey;
  }

  async request<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<SocResponse<T>> {
    try {
      const url = `${this.baseUrl}${path}`;

      const response = await socFetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
      });

      const { data, error: parseError } = await parseResponseBody<T>(response);
      return {
        ok: response.ok && !parseError,
        data,
        error: parseError,
        status: response.status,
      };
    } catch (error) {
      return {
        ok: false,
        error: socRequestError(error),
      };
    }
  }
}

// Cortex client
export class CortexClient {
  readonly operationScope: string;
  private baseUrl: string;
  private apiKey: string;

  constructor(config: NonNullable<SocConfig["cortex"]>) {
    this.operationScope = targetScope(config.url);
    this.baseUrl = config.url.replace(/\/$/, "");
    this.apiKey = config.apiKey;
  }

  async request<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<SocResponse<T>> {
    try {
      const url = `${this.baseUrl}${path}`;

      const response = await socFetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
      });

      const { data, error: parseError } = await parseResponseBody<T>(response);
      return {
        ok: response.ok && !parseError,
        data,
        error: parseError,
        status: response.status,
      };
    } catch (error) {
      return {
        ok: false,
        error: socRequestError(error),
      };
    }
  }
}

// MISP client
export class MispClient {
  readonly operationScope: string;
  private baseUrl: string;
  private apiKey: string;
  private verifySsl: boolean;

  constructor(config: NonNullable<SocConfig["misp"]>) {
    this.operationScope = targetScope(config.url);
    this.baseUrl = config.url.replace(/\/$/, "");
    this.apiKey = config.apiKey;
    this.verifySsl = config.verifySsl;
  }

  async request<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<SocResponse<T>> {
    try {
      const url = `${this.baseUrl}${path}`;

      const response = await socFetch(url, {
        method,
        headers: {
          Authorization: this.apiKey,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
        rejectUnauthorized: this.verifySsl,
      });

      const { data, error: parseError } = await parseResponseBody<T>(response);
      return {
        ok: response.ok && !parseError,
        data,
        error: parseError,
        status: response.status,
      };
    } catch (error) {
      return {
        ok: false,
        error: socRequestError(error),
      };
    }
  }
}
