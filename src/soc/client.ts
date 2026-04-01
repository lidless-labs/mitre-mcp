import type { SocConfig } from "../types.js";

export interface SocResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
  status?: number;
}

// Custom fetch that handles self-signed certs
async function socFetch(
  url: string,
  options: RequestInit & { rejectUnauthorized?: boolean } = {},
): Promise<Response> {
  const { rejectUnauthorized, ...fetchOpts } = options;

  // Node 18+ supports custom TLS options via the dispatcher,
  // but the simplest cross-version approach is setting the env var.
  // For individual requests, we use the global agent approach.
  if (rejectUnauthorized === false) {
    // Temporarily allow self-signed certs
    const prev = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    try {
      return await fetch(url, fetchOpts);
    } finally {
      if (prev === undefined) {
        delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      } else {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = prev;
      }
    }
  }

  return fetch(url, fetchOpts);
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

      const data = (await response.json()) as T;
      return { ok: response.ok, data, status: response.status };
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

      const data = (await response.json()) as T;
      return { ok: response.ok, data, status: response.status };
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

      const data = (await response.json()) as T;
      return { ok: response.ok, data, status: response.status };
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

      const data = (await response.json()) as T;
      return { ok: response.ok, data, status: response.status };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}
