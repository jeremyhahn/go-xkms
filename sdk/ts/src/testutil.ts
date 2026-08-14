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

/** Test-only fake fetch. Not exported from the package entry point. */

export interface RecordedCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  credentials: string | undefined;
}

export interface FakeResponseSpec {
  status?: number;
  body?: unknown;
  /** Raw text body (overrides `body`). */
  text?: string;
  headers?: Record<string, string>;
}

export interface FakeFetch {
  fetch: typeof fetch;
  calls: RecordedCall[];
  /** Queue the response for the next call (FIFO; last spec repeats). */
  respond: (spec: FakeResponseSpec) => void;
}

/** newFakeFetch records calls and plays back queued responses. */
export function newFakeFetch(initial?: FakeResponseSpec): FakeFetch {
  const calls: RecordedCall[] = [];
  const queue: FakeResponseSpec[] = initial !== undefined ? [initial] : [];
  let last: FakeResponseSpec = {};

  const impl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
      headers[k] = v;
    }
    calls.push({
      url: String(input),
      method: init?.method ?? 'GET',
      headers,
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : init?.body,
      credentials: init?.credentials,
    });

    const spec = queue.shift() ?? last;
    last = spec;
    const status = spec.status ?? 200;
    const text =
      spec.text !== undefined
        ? spec.text
        : spec.body !== undefined
          ? JSON.stringify(spec.body)
          : '';
    if (status === 204) {
      return new Response(null, { status, headers: spec.headers ?? {} });
    }
    return new Response(text, { status, headers: spec.headers ?? {} });
  };

  return {
    fetch: impl as typeof fetch,
    calls,
    respond: (spec) => queue.push(spec),
  };
}
