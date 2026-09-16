/**
 * HTTP API client built on fetch().
 *
 * Follows the go-ledgely singleton pattern with typed request helpers and
 * automatic error handling, auth-token injection and tenant header support.
 */

import { getApiBaseUrl } from './transport';
import type { ApiResponse, ApiError } from './types';

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

export class ApiClientError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiClientError';
  }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class ApiClient {
  private authToken: string | null = null;
  private tenantId: string | null = null;

  /** Set the bearer token used for authenticated requests. */
  setAuthToken(token: string | null): void {
    this.authToken = token;
  }

  /** Set the tenant ID sent via the X-Tenant-ID header. */
  setTenantId(id: string | null): void {
    this.tenantId = id;
  }

  // -----------------------------------------------------------------------
  // Public helpers
  // -----------------------------------------------------------------------

  async get<T>(path: string, params?: Record<string, unknown>): Promise<T> {
    return this.request<T>('GET', path, undefined, params);
  }

  async post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  async put<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('PUT', path, body);
  }

  async patch<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('PATCH', path, body);
  }

  async delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }

  // -----------------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------------

  private buildUrl(path: string, params?: Record<string, unknown>): string {
    const base = getApiBaseUrl();
    const url = new URL(`${base}${path}`, window.location.origin);

    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null && value !== '') {
          url.searchParams.set(key, String(value));
        }
      }
    }

    return url.toString();
  }

  private buildHeaders(): HeadersInit {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };

    // The desktop API is in-process and same-origin, so it carries no token;
    // a server-hosted deployment sets one through setAuthToken().
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }

    if (this.tenantId) {
      headers['X-Tenant-ID'] = this.tenantId;
    }

    return headers;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    params?: Record<string, unknown>,
  ): Promise<T> {
    const url = this.buildUrl(path, params);

    const init: RequestInit = {
      method,
      headers: this.buildHeaders(),
    };

    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }

    const res = await fetch(url, init);
    return this.handleResponse<T>(res);
  }

  private async handleResponse<T>(res: Response): Promise<T> {
    // Handle 204 No Content
    if (res.status === 204) {
      return undefined as unknown as T;
    }

    let json: ApiResponse<T>;
    try {
      json = (await res.json()) as ApiResponse<T>;
    } catch (_e) {
      throw new ApiClientError(
        res.status,
        'parse_error',
        'Failed to parse response body',
      );
    }

    // Normalise the error envelope: some handlers return {error: {code, message}}
    // while the trusted-acme-client REST API returns {error: "message string"}.
    const extractError = (raw: unknown): { code: string; message: string } | null => {
      if (raw === undefined || raw === null) return null;
      if (typeof raw === 'string') {
        return { code: 'server_error', message: raw };
      }
      if (typeof raw === 'object') {
        const obj = raw as Partial<ApiError>;
        return {
          code: obj.code ?? 'server_error',
          message: obj.message ?? JSON.stringify(raw),
        };
      }
      return { code: 'server_error', message: String(raw) };
    };

    // 401 - clear auth state
    if (res.status === 401) {
      this.authToken = null;
      const err = extractError(json.error);
      throw new ApiClientError(
        401,
        err?.code ?? 'unauthorized',
        err?.message ?? 'Unauthorized',
      );
    }

    if (!res.ok || json.error) {
      const err = extractError(json.error);
      throw new ApiClientError(
        res.status,
        err?.code ?? 'unknown',
        err?.message ?? `Request failed with status ${res.status}`,
      );
    }

    // Unwrap { data: ... } envelope when present
    if (json.data !== undefined) {
      return json.data;
    }

    return json as unknown as T;
  }
}

/** Singleton API client instance. */
export const apiClient = new ApiClient();
