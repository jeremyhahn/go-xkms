// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * The single HTTP request core every domain client routes through. Nothing
 * else in the SDK builds URLs, attaches Authorization headers, or decodes
 * error envelopes — this module is the one place those concerns live.
 */

import type { TokenProvider, XkmsClientConfig } from './config.js';
import { XkmsNetworkError, parseErrorEnvelope } from './errors.js';

/** Query values; undefined / null / '' members are omitted from the URL. */
export type QueryParams = Record<string, string | number | boolean | undefined | null>;

/** HTTP methods used by the xkms REST surface. */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';

/** Per-request options for the core. */
export interface RequestOptions {
  /** Query string parameters appended to the path. */
  query?: QueryParams;
  /** JSON body; serialized when not undefined. */
  body?: unknown;
  /** Extra request headers (e.g. X-Session-Id for WebAuthn ceremonies). */
  headers?: Record<string, string>;
  /** Attach `Authorization: Bearer <token>` (default true when a token provider exists). */
  auth?: boolean;
  /** fetch credentials mode (loginCert uses 'include' for the mTLS exchange). */
  credentials?: RequestCredentials;
  /** How to decode a successful response body. Default 'json'; 204 always yields undefined. */
  parse?: 'json' | 'text' | 'void';
  /** Non-2xx statuses that resolve instead of throwing (e.g. HEAD 404 existence probes). */
  okOn?: number[];
}

/** A decoded response paired with the raw Response (for header access). */
export interface HttpResult<T> {
  data: T;
  response: Response;
}

/** buildURL joins baseURL + path and encodes query parameters. */
export function buildURL(baseURL: string, path: string, query?: QueryParams): string {
  const base = baseURL.replace(/\/+$/, '');
  let url = `${base}${path.startsWith('/') ? path : `/${path}`}`;
  if (query) {
    const parts: string[] = [];
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === '') {
        continue;
      }
      parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
    }
    if (parts.length > 0) {
      url += `?${parts.join('&')}`;
    }
  }
  return url;
}

/** encodePathSegment escapes a single URL path segment (share server URLs, hostnames, ...). */
export function encodePathSegment(segment: string): string {
  return encodeURIComponent(segment);
}

/** HttpCore issues authenticated JSON requests against one xkms server. */
export class HttpCore {
  readonly baseURL: string;
  private readonly token: TokenProvider | undefined;
  private readonly fetchImpl: typeof fetch;

  constructor(config: Pick<XkmsClientConfig, 'baseURL' | 'token' | 'fetch'>) {
    this.baseURL = config.baseURL;
    this.token = config.token;
    // Bind to globalThis so browser fetch keeps its receiver.
    this.fetchImpl = config.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** request performs a call and returns the decoded body. */
  async request<T>(method: HttpMethod, path: string, opts: RequestOptions = {}): Promise<T> {
    const { data } = await this.requestRaw<T>(method, path, opts);
    return data;
  }

  /** requestRaw performs a call and returns the decoded body plus the Response. */
  async requestRaw<T>(
    method: HttpMethod,
    path: string,
    opts: RequestOptions = {},
  ): Promise<HttpResult<T>> {
    const url = buildURL(this.baseURL, path, opts.query);
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };

    const useAuth = opts.auth !== false;
    if (useAuth && this.token && headers['Authorization'] === undefined) {
      const token = await this.token();
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }

    const init: RequestInit = { method, headers };
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opts.body);
    }
    if (opts.credentials !== undefined) {
      init.credentials = opts.credentials;
    }

    let response: Response;
    try {
      response = await this.fetchImpl(url, init);
    } catch (err) {
      throw new XkmsNetworkError(`request to ${url} failed: ${String(err)}`, err);
    }

    const correlationId = response.headers.get('X-Correlation-ID') ?? undefined;

    if (!response.ok && !(opts.okOn ?? []).includes(response.status)) {
      let bodyText = '';
      try {
        bodyText = await response.text();
      } catch {
        // Body unreadable; the status-only error still carries the essentials.
      }
      throw parseErrorEnvelope(response.status, response.statusText, bodyText, correlationId);
    }

    const parse = opts.parse ?? 'json';
    if (parse === 'void' || response.status === 204 || method === 'HEAD') {
      return { data: undefined as T, response };
    }
    if (parse === 'text') {
      return { data: (await response.text()) as T, response };
    }
    if (!response.ok) {
      // okOn short-circuit for JSON parses: surface undefined rather than
      // attempting to decode an error page.
      return { data: undefined as T, response };
    }
    const text = await response.text();
    if (text === '') {
      return { data: undefined as T, response };
    }
    return { data: JSON.parse(text) as T, response };
  }
}
