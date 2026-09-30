// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

import type { HttpCore } from '../http.js';
import type {
  AllKeyVersionsResponse,
  KeyVersionStateResponse,
  ListKeyVersionsResponse,
  RotateScopeKeysResponse,
} from '../types/keyVersions.js';

const BASE = '/api/v1/keys';

function versionsPath(id: string, suffix = ''): string {
  return `${BASE}/${encodeURIComponent(id)}/versions${suffix}`;
}

/**
 * Key versions. A version is its own backend key: rotating a key
 * (`keys.rotate`) creates its next version and makes it current. Every call
 * acts in the caller's tenant; `rotateAll` alone may name another tenant,
 * which only a system caller may do.
 */
export class KeyVersionsClient {
  constructor(private readonly http: HttpCore) {}

  /** GET /api/v1/keys/{id}/versions?backend= */
  list(id: string, backend: string): Promise<ListKeyVersionsResponse> {
    return this.http.request('GET', versionsPath(id), { query: { backend } });
  }

  /** POST /api/v1/keys/{id}/versions/{version}/enable?backend= */
  enable(id: string, version: number, backend: string): Promise<KeyVersionStateResponse> {
    return this.http.request('POST', versionsPath(id, `/${version}/enable`), { query: { backend } });
  }

  /** POST /api/v1/keys/{id}/versions/{version}/disable?backend= — the current version cannot be disabled. */
  disable(id: string, version: number, backend: string): Promise<KeyVersionStateResponse> {
    return this.http.request('POST', versionsPath(id, `/${version}/disable`), { query: { backend } });
  }

  /** POST /api/v1/keys/{id}/versions/{version}/retire?backend= — deletes the version's key material for good. */
  retire(id: string, version: number, backend: string): Promise<KeyVersionStateResponse> {
    return this.http.request('POST', versionsPath(id, `/${version}/retire`), { query: { backend } });
  }

  /** POST /api/v1/keys/{id}/versions/enable-all?backend= */
  enableAll(id: string, backend: string): Promise<AllKeyVersionsResponse> {
    return this.http.request('POST', versionsPath(id, '/enable-all'), { query: { backend } });
  }

  /** POST /api/v1/keys/{id}/versions/disable-all?backend= — never reaches the current version. */
  disableAll(id: string, backend: string): Promise<AllKeyVersionsResponse> {
    return this.http.request('POST', versionsPath(id, '/disable-all'), { query: { backend } });
  }

  /** POST /api/v1/keys/rotate-all — rotates every key of the caller's tenant, or of tenantId (system callers only). */
  rotateAll(tenantId?: string): Promise<RotateScopeKeysResponse> {
    return this.http.request('POST', `${BASE}/rotate-all`, {
      body: tenantId ? { tenant_id: tenantId } : {},
    });
  }
}
