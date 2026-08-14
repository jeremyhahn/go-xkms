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
import type { PageQuery } from '../types/common.js';
import type {
  AttestKeyRequest,
  AttestKeyResponse,
  CopyKeyRequest,
  CopyKeyResponse,
  DecryptRequest,
  DecryptResponse,
  DeleteKeyResponse,
  DeriveKeyECDHRequest,
  DeriveKeyECDHResponse,
  EncryptAsymRequest,
  EncryptAsymResponse,
  EncryptRequest,
  EncryptResponse,
  ExportKeyMaterialResponse,
  ExportKeyRequest,
  ExportKeyResponse,
  GenerateKeyRequest,
  GenerateKeyResponse,
  GetImportParametersRequest,
  GetImportParametersResponse,
  GetKeyResponse,
  ImportKeyRequest,
  ImportKeyResponse,
  ListKeysResponse,
  RotateKeyResponse,
  SignRequest,
  SignResponse,
  UnwrapKeyByIDRequest,
  UnwrapKeyByIDResponse,
  UnwrapKeyRequest,
  UnwrapKeyResponse,
  VerifyRequest,
  VerifyResponse,
  WrapKeyByIDRequest,
  WrapKeyByIDResponse,
  WrapKeyRequest,
  WrapKeyResponse,
} from '../types/keys.js';

const BASE = '/api/v1/keys';

function keyPath(id: string, suffix = ''): string {
  return `${BASE}/${encodeURIComponent(id)}${suffix}`;
}

/** Key lifecycle and crypto operations. */
export class KeysClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/keys */
  generate(req: GenerateKeyRequest): Promise<GenerateKeyResponse> {
    return this.http.request('POST', BASE, { body: req });
  }

  /** GET /api/v1/keys?backend= */
  list(backend?: string, page?: PageQuery): Promise<ListKeysResponse> {
    return this.http.request('GET', BASE, { query: { backend, ...page } });
  }

  /** GET /api/v1/keys/{id}?backend= */
  get(id: string, backend?: string): Promise<GetKeyResponse> {
    return this.http.request('GET', keyPath(id), { query: { backend } });
  }

  /** DELETE /api/v1/keys/{id}?backend= */
  delete(id: string, backend?: string): Promise<DeleteKeyResponse> {
    return this.http.request('DELETE', keyPath(id), { query: { backend } });
  }

  /**
   * POST /api/v1/keys/{id}/sign — the backend rides both the body and the
   * `?backend=` query (the handler honors the query override; clustered
   * deployments require it).
   */
  sign(id: string, req: SignRequest): Promise<SignResponse> {
    return this.http.request('POST', keyPath(id, '/sign'), {
      body: req,
      query: { backend: req.backend },
    });
  }

  /** POST /api/v1/keys/{id}/verify */
  verify(id: string, req: VerifyRequest): Promise<VerifyResponse> {
    return this.http.request('POST', keyPath(id, '/verify'), {
      body: req,
      query: { backend: req.backend },
    });
  }

  /** POST /api/v1/keys/{id}/rotate?backend= (backend query is required). */
  rotate(id: string, backend: string): Promise<RotateKeyResponse> {
    return this.http.request('POST', keyPath(id, '/rotate'), { query: { backend } });
  }

  /** POST /api/v1/keys/{id}/encrypt */
  encrypt(id: string, req: EncryptRequest): Promise<EncryptResponse> {
    return this.http.request('POST', keyPath(id, '/encrypt'), { body: req });
  }

  /** POST /api/v1/keys/{id}/decrypt */
  decrypt(id: string, req: DecryptRequest): Promise<DecryptResponse> {
    return this.http.request('POST', keyPath(id, '/decrypt'), { body: req });
  }

  /** POST /api/v1/keys/{id}/encrypt-asym */
  encryptAsym(id: string, req: EncryptAsymRequest): Promise<EncryptAsymResponse> {
    return this.http.request('POST', keyPath(id, '/encrypt-asym'), { body: req });
  }

  /** POST /api/v1/keys/import-params */
  importParams(req: GetImportParametersRequest): Promise<GetImportParametersResponse> {
    return this.http.request('POST', `${BASE}/import-params`, { body: req });
  }

  /** POST /api/v1/keys/wrap */
  wrap(req: WrapKeyRequest): Promise<WrapKeyResponse> {
    return this.http.request('POST', `${BASE}/wrap`, { body: req });
  }

  /** POST /api/v1/keys/unwrap */
  unwrap(req: UnwrapKeyRequest): Promise<UnwrapKeyResponse> {
    return this.http.request('POST', `${BASE}/unwrap`, { body: req });
  }

  /** POST /api/v1/keys/import */
  import(req: ImportKeyRequest): Promise<ImportKeyResponse> {
    return this.http.request('POST', `${BASE}/import`, { body: req });
  }

  /** POST /api/v1/keys/{id}/export */
  export(id: string, req: ExportKeyRequest): Promise<ExportKeyResponse> {
    return this.http.request('POST', keyPath(id, '/export'), {
      body: req,
      query: { backend: req.backend },
    });
  }

  /** POST /api/v1/keys/copy */
  copy(req: CopyKeyRequest): Promise<CopyKeyResponse> {
    return this.http.request('POST', `${BASE}/copy`, { body: req });
  }

  /** POST /api/v1/attest */
  attest(req: AttestKeyRequest): Promise<AttestKeyResponse> {
    return this.http.request('POST', '/api/v1/attest', { body: req });
  }

  /** POST /api/v1/keys/derive-ecdh */
  deriveECDH(req: DeriveKeyECDHRequest): Promise<DeriveKeyECDHResponse> {
    return this.http.request('POST', `${BASE}/derive-ecdh`, { body: req });
  }

  /** POST /api/v1/keys/{id}/export-material?backend= */
  exportMaterial(id: string, backend: string): Promise<ExportKeyMaterialResponse> {
    return this.http.request('POST', keyPath(id, '/export-material'), {
      query: { backend },
    });
  }

  /** POST /api/v1/keys/wrap-by-id */
  wrapById(req: WrapKeyByIDRequest): Promise<WrapKeyByIDResponse> {
    return this.http.request('POST', `${BASE}/wrap-by-id`, { body: req });
  }

  /** POST /api/v1/keys/unwrap-by-id */
  unwrapById(req: UnwrapKeyByIDRequest): Promise<UnwrapKeyByIDResponse> {
    return this.http.request('POST', `${BASE}/unwrap-by-id`, { body: req });
  }
}
