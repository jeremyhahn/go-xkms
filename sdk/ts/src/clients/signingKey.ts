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
  ListSigningKeyBindingsResponse,
  SetSigningKeyBindingRequest,
  SignCoRIMRequest,
  SignedCoRIM,
  SignImageRequest,
  SignedImage,
  SigningKeyBinding,
  SigningKeyResolution,
} from '../types/signingKey.js';

const BASE = '/api/v1/attestation/signing-keys';

/**
 * Repository signing-key bindings of the caller's tenant (go-xkms#1697). A
 * repository path holds slashes, so the calls that name one carry it in the
 * repository query parameter. Mirrors pkg/api/rest/handlers_signing_key.go.
 */
export class SigningKeyClient {
  constructor(private readonly http: HttpCore) {}

  /** PUT /api/v1/attestation/signing-keys — names the key that signs a repository. */
  set(req: SetSigningKeyBindingRequest): Promise<SigningKeyBinding> {
    return this.http.request('PUT', BASE, { body: req });
  }

  /** GET /api/v1/attestation/signing-keys/binding?repository= — a repository's binding. */
  get(repository: string): Promise<SigningKeyBinding> {
    return this.http.request('GET', `${BASE}/binding`, { query: { repository } });
  }

  /** GET /api/v1/attestation/signing-keys — the tenant's bindings. */
  list(): Promise<ListSigningKeyBindingsResponse> {
    return this.http.request('GET', BASE);
  }

  /** DELETE /api/v1/attestation/signing-keys/binding?repository= (204). */
  async delete(repository: string): Promise<void> {
    await this.http.request<void>('DELETE', `${BASE}/binding`, { query: { repository } });
  }

  /** GET /api/v1/attestation/signing-keys/resolve?repository= — the key that signs a repository. */
  resolve(repository: string): Promise<SigningKeyResolution> {
    return this.http.request('GET', `${BASE}/resolve`, { query: { repository } });
  }

  /**
   * POST /api/v1/attestation/signing-keys/sign-corim — signs a repository's
   * CoRIM with the key it resolves to, draft-ietf-rats-corim-11 §4.2.
   */
  signCoRIM(req: SignCoRIMRequest): Promise<SignedCoRIM> {
    return this.http.request('POST', `${BASE}/sign-corim`, { body: req });
  }

  /**
   * POST /api/v1/attestation/signing-keys/sign-image — signs an image with
   * the key its repository resolves to and pushes the attestation to the
   * image's registry with the request's credentials. A request carrying
   * registry credentials goes only to an https:// base URL, without
   * following redirects, unless allowInsecureTransport is set (ruling 152):
   * otherwise it throws XkmsInsecureTransportError before anything is sent.
   */
  signImage(req: SignImageRequest): Promise<SignedImage> {
    return this.http.request('POST', `${BASE}/sign-image`, {
      body: req,
      secureChannel: req.registry !== undefined,
    });
  }
}
