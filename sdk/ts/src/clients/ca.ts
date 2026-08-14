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
import type {
  EnrollDeviceRequest,
  EnrollDeviceResponse,
  GenerateCRLRequest,
  GenerateCRLResponse,
  GetCABundleResponse,
  GetCACertificateResponse,
  IsRevokedResponse,
  IssueAKCertificateRequest,
  IssueAKCertificateResponse,
  IssueCertificateRequest,
  IssueCertificateResponse,
  IssueEKCertificateRequest,
  IssueEKCertificateResponse,
  RevokeCertificateRequest,
  RevokeCertificateResponse,
  SignCSRRequest,
  SignCSRResponse,
  SignTCGCSRRequest,
  SignTCGCSRResponse,
} from '../types/ca.js';

const BASE = '/api/v1/ca';

/** TrustedCA operations, including the TCG (TPM EK/AK/IDevID) surface. */
export class CaClient {
  constructor(private readonly http: HttpCore) {}

  /** GET /api/v1/ca/bundle?store_type=&algorithm= */
  bundle(storeType?: string, algorithm?: string): Promise<GetCABundleResponse> {
    return this.http.request('GET', `${BASE}/bundle`, {
      query: { store_type: storeType, algorithm },
    });
  }

  /** GET /api/v1/ca/certificate?identity= */
  certificate(identity?: string): Promise<GetCACertificateResponse> {
    return this.http.request('GET', `${BASE}/certificate`, { query: { identity } });
  }

  /** POST /api/v1/ca/sign-csr */
  signCSR(req: SignCSRRequest): Promise<SignCSRResponse> {
    return this.http.request('POST', `${BASE}/sign-csr`, { body: req });
  }

  /** POST /api/v1/ca/issue */
  issue(req: IssueCertificateRequest): Promise<IssueCertificateResponse> {
    return this.http.request('POST', `${BASE}/issue`, { body: req });
  }

  /** POST /api/v1/ca/revoke */
  revoke(req: RevokeCertificateRequest): Promise<RevokeCertificateResponse> {
    return this.http.request('POST', `${BASE}/revoke`, { body: req });
  }

  /** POST /api/v1/ca/crl */
  generateCRL(req?: GenerateCRLRequest): Promise<GenerateCRLResponse> {
    return this.http.request('POST', `${BASE}/crl`, { body: req ?? {} });
  }

  /** GET /api/v1/ca/revoked/{serial} */
  isRevoked(serial: string): Promise<IsRevokedResponse> {
    return this.http.request('GET', `${BASE}/revoked/${encodeURIComponent(serial)}`);
  }

  /** POST /api/v1/ca/tcg/ek */
  issueEK(req: IssueEKCertificateRequest): Promise<IssueEKCertificateResponse> {
    return this.http.request('POST', `${BASE}/tcg/ek`, { body: req });
  }

  /** POST /api/v1/ca/tcg/ak */
  issueAK(req: IssueAKCertificateRequest): Promise<IssueAKCertificateResponse> {
    return this.http.request('POST', `${BASE}/tcg/ak`, { body: req });
  }

  /** POST /api/v1/ca/tcg/sign-csr */
  signTCGCSR(req: SignTCGCSRRequest): Promise<SignTCGCSRResponse> {
    return this.http.request('POST', `${BASE}/tcg/sign-csr`, { body: req });
  }

  /** POST /api/v1/ca/tcg/enroll */
  enrollDevice(req: EnrollDeviceRequest): Promise<EnrollDeviceResponse> {
    return this.http.request('POST', `${BASE}/tcg/enroll`, { body: req });
  }

  /**
   * GET /v1/ca/bootstrap — the unauthenticated go-truststrap bootstrap
   * endpoint; returns the raw PEM bundle text
   * (application/pem-certificate-chain), not JSON.
   */
  bootstrapBundle(): Promise<string> {
    return this.http.request('GET', '/v1/ca/bootstrap', { auth: false, parse: 'text' });
  }
}
