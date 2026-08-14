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
import type { SuccessResponse } from '../types/common.js';
import type {
  GeneratePIVCSRRequest,
  GeneratePIVCSRResponse,
  GeneratePIVKeyRequest,
  GeneratePIVKeyResponse,
  GetPIVCertificateResponse,
  ListPIVSlotsResponse,
  StorePIVCertificateRequest,
} from '../types/piv.js';

const BASE = '/api/v1/piv';

function slotPath(slot: string, suffix: string): string {
  return `${BASE}/slots/${encodeURIComponent(slot)}${suffix}`;
}

/** PIV smart-card slot operations. */
export class PivClient {
  constructor(private readonly http: HttpCore) {}

  /** GET /api/v1/piv/slots?backend= */
  listSlots(backend?: string): Promise<ListPIVSlotsResponse> {
    return this.http.request('GET', `${BASE}/slots`, { query: { backend } });
  }

  /** GET /api/v1/piv/slots/{slot}/certificate?backend=&format= */
  getCertificate(
    slot: string,
    backend?: string,
    format?: string,
  ): Promise<GetPIVCertificateResponse> {
    return this.http.request('GET', slotPath(slot, '/certificate'), {
      query: { backend, format },
    });
  }

  /** POST /api/v1/piv/slots/{slot}/certificate */
  storeCertificate(slot: string, req: StorePIVCertificateRequest): Promise<SuccessResponse> {
    return this.http.request('POST', slotPath(slot, '/certificate'), { body: req });
  }

  /** DELETE /api/v1/piv/slots/{slot}/certificate?backend= */
  deleteCertificate(slot: string, backend?: string): Promise<SuccessResponse> {
    return this.http.request('DELETE', slotPath(slot, '/certificate'), {
      query: { backend },
    });
  }

  /** POST /api/v1/piv/slots/{slot}/generate */
  generateKey(slot: string, req: GeneratePIVKeyRequest): Promise<GeneratePIVKeyResponse> {
    return this.http.request('POST', slotPath(slot, '/generate'), { body: req });
  }

  /** POST /api/v1/piv/slots/{slot}/import */
  importCertificate(slot: string, req: StorePIVCertificateRequest): Promise<SuccessResponse> {
    return this.http.request('POST', slotPath(slot, '/import'), { body: req });
  }

  /** GET /api/v1/piv/slots/{slot}/export?backend=&format= */
  exportCertificate(
    slot: string,
    backend?: string,
    format?: string,
  ): Promise<GetPIVCertificateResponse> {
    return this.http.request('GET', slotPath(slot, '/export'), {
      query: { backend, format },
    });
  }

  /** POST /api/v1/piv/slots/{slot}/csr */
  generateCSR(slot: string, req: GeneratePIVCSRRequest): Promise<GeneratePIVCSRResponse> {
    return this.http.request('POST', slotPath(slot, '/csr'), { body: req });
  }
}
