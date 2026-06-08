import { Agent } from "undici";
import type { SocConfig } from "../types.js";

export interface SocResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
  status?: number;
}

// Custom fetch that handles self-signed certs.
//
// When `rejectUnauthorized === false` we scope the relaxed TLS policy to a
// single request via a per-request undici Agent passed as the `dispatcher`.
// This avoids ever mutating the process-global `NODE_TLS_REJECT_UNAUTHORIZED`,
// which would disable certificate validation for ALL concurrent outbound
// requests (a MITM window that could leak SOC credentials).
async function socFetch(
  url: string,
  options: RequestInit & { rejectUnauthorized?: boolean } = {},
): Promise<Response> {
  const { rejectUnauthorized, ...fetchOpts } = options;

  if (rejectUnauthorized === false) {
    const agent = new Agent({ connect: { rejectUnauthorized: false } });
    try {
      // `dispatcher` is an undici extension to RequestInit honored by the
      // global fetch implementation in Node 18+.
      return await fetch(url, {
        ...fetchOpts,
        dispatcher: agent,
      } as RequestInit);
    } finally {
      // Release the per-request connection pool promptly.
      void agent.close();
    }
  }

  return fetch(url, fetchOpts);
}

// Safely read a SOC response body. Many SOC platforms return HTML/plain-text
// error pages (auth redirects, reverse-proxy 502s, rate limiters) with a
// success-looking shape; calling `.json()` unconditionally throws and masks
// the real HTTP status. Guard on content-type and fall back to text.
async function parseResponseBody<T>(
  response: Response,
): Promise<{ data?: T; error?: string }> {
  const contentType = response.headers.get("content-type") || "";
  const raw = await response.text();

  if (contentType.includes("application/json") || contentType.includes("+json")) {
    if (raw.length === 0) return { data: undefined };
    try {
      return { data: JSON.parse(raw) as T };
    } catch {
      // Declared JSON but unparseable: surface a snippet instead of crashing.
      return {
        error: `Non-JSON response (HTTP ${response.status}): ${raw.slice(0, 300)}`,
      };
    }
  }

  // Non-JSON body: try to parse anyway (some servers omit the header), else
  // surface the text so the caller sees the real status/error.
  if (raw.length === 0) return { data: undefined };
  try {
    return { data: JSON.parse(raw) as T };
  } catch {
    return {
      error: `Non-JSON response (HTTP ${response.status}): ${raw.slice(0, 300)}`,
    };
  }
}

// Wazuh client
export class WazuhClient {
  private baseUrl: string;
  private username: string;
  private password: string;
  private verifySsl: boolean;
  private token: string | null = null;
  private tokenExpiry = 0;

  constructor(config: NonNullable<SocConfig["wazuh"]>) {
    this.baseUrl = config.url.replace(/\/$/, "");
    this.username = config.username;
    this.password = config.password;
    this.verifySsl = config.verifySsl;
  }

  private async authenticate(): Promise<string> {
    if (this.token && Date.now() < this.tokenExpiry) {
      return this.token;
    }

    const response = await socFetch(
      `${this.baseUrl}/security/user/authenticate`,
      {
        method: "POST",
        headers: {
          Authorization: `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`,
        },
        rejectUnauthorized: this.verifySsl,
      },
    );

    if (!response.ok) {
      throw new Error(`Wazuh auth failed: ${response.status} ${response.statusText}`);
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
      const token = await this.authenticate();
      const url = `${this.baseUrl}${path}`;

      const response = await socFetch(url, {
        method,
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
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

// TheHive client
export class TheHiveClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(config: NonNullable<SocConfig["thehive"]>) {
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
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

// Cortex client
export class CortexClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(config: NonNullable<SocConfig["cortex"]>) {
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
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

// MISP client
export class MispClient {
  private baseUrl: string;
  private apiKey: string;
  private verifySsl: boolean;

  constructor(config: NonNullable<SocConfig["misp"]>) {
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
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}
