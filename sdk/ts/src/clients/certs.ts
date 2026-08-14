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

import type { HttpCore } from '../http.js';
import type { PageQuery, SuccessResponse } from '../types/common.js';
import type {
  GetCertChainResponse,
  GetCertResponse,
  GetTLSCertificateResponse,
  ListCertsResponse,
  SaveCertChainRequest,
  SaveCertRequest,
} from '../types/certs.js';

const BASE = '/api/v1/certs';

function certPath(id: string, suffix = ''): string {
  return `${BASE}/${encodeURIComponent(id)}${suffix}`;
}

/** Certificate storage attached to backend keys. */
export class CertsClient {
  constructor(private readonly http: HttpCore) {}

  /**
   * POST /api/v1/certs?key_id=&backend= — the handler reads key_id and
   * backend from the query string; the body carries the PEM.
   */
  save(keyId: string, backend: string, req: SaveCertRequest): Promise<SuccessResponse> {
    return this.http.request('POST', BASE, {
      body: req,
      query: { key_id: keyId, backend },
    });
  }

  /** GET /api/v1/certs?backend= */
  list(backend?: string, page?: PageQuery): Promise<ListCertsResponse> {
    return this.http.request('GET', BASE, { query: { backend, ...page } });
  }

  /** GET /api/v1/certs/{id}?backend= */
  get(id: string, backend: string): Promise<GetCertResponse> {
    return this.http.request('GET', certPath(id), { query: { backend } });
  }

  /** DELETE /api/v1/certs/{id}?backend= */
  delete(id: string, backend: string): Promise<SuccessResponse> {
    return this.http.request('DELETE', certPath(id), { query: { backend } });
  }

  /** HEAD /api/v1/certs/{id}?backend= — true when the certificate exists. */
  async exists(id: string, backend: string): Promise<boolean> {
    const { response } = await this.http.requestRaw<void>('HEAD', certPath(id), {
      query: { backend },
      parse: 'void',
      okOn: [404],
    });
    return response.ok;
  }

  /** POST /api/v1/certs/{id}/chain */
  saveChain(id: string, req: SaveCertChainRequest): Promise<SuccessResponse> {
    return this.http.request('POST', certPath(id, '/chain'), {
      body: req,
      query: { backend: req.backend },
    });
  }

  /** GET /api/v1/certs/{id}/chain?backend= */
  getChain(id: string, backend?: string): Promise<GetCertChainResponse> {
    return this.http.request('GET', certPath(id, '/chain'), { query: { backend } });
  }

  /** GET /api/v1/tls/{id}?backend= — private key + cert + chain bundle. */
  tlsBundle(id: string, backend?: string): Promise<GetTLSCertificateResponse> {
    return this.http.request('GET', `/api/v1/tls/${encodeURIComponent(id)}`, {
      query: { backend },
    });
  }
}
