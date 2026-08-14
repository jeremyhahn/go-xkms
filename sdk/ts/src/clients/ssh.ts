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

import { encodePathSegment, type HttpCore } from '../http.js';
import type {
  SSHAddAuthorizedKeyRequest,
  SSHAddKnownHostRequest,
  SSHAuthorizedEntry,
  SSHAuthorizedListResponse,
  SSHEmitRequest,
  SSHEmitResponse,
  SSHGenerateKeyRequest,
  SSHImportKeyRequest,
  SSHKey,
  SSHKeyListResponse,
  SSHPinListResponse,
  SSHPublicKey,
  SSHSignRequest,
  SSHSignResponse,
  SSHVerifyAuthorizedRequest,
  SSHVerifyKnownHostRequest,
} from '../types/ssh.js';

const BASE = '/xkms/v1/ssh';

function keyPath(scope: string, owner: string, name: string, suffix = ''): string {
  return `${BASE}/keys/${encodePathSegment(scope)}/${encodePathSegment(owner)}/${encodePathSegment(name)}${suffix}`;
}

function authorizedPath(scope: string, owner: string, name: string): string {
  return `${BASE}/authorized-keys/${encodePathSegment(scope)}/${encodePathSegment(owner)}/${encodePathSegment(name)}`;
}

/** SSH key, known-host, and authorized-key management over REST (/xkms/v1/ssh). */
export class SshClient {
  constructor(private readonly http: HttpCore) {}

  // ------------------------------------------------------------------
  // Keys
  // ------------------------------------------------------------------

  /** POST /xkms/v1/ssh/keys */
  generateKey(req: SSHGenerateKeyRequest): Promise<SSHKey> {
    return this.http.request('POST', `${BASE}/keys`, { body: req });
  }

  /** POST /xkms/v1/ssh/keys/import */
  importKey(req: SSHImportKeyRequest): Promise<SSHKey> {
    return this.http.request('POST', `${BASE}/keys/import`, { body: req });
  }

  /** GET /xkms/v1/ssh/keys?scope=&owner= */
  listKeys(scope?: string, owner?: string): Promise<SSHKeyListResponse> {
    return this.http.request('GET', `${BASE}/keys`, { query: { scope, owner } });
  }

  /** GET /xkms/v1/ssh/keys/{scope}/{owner}/{name} */
  getKey(scope: string, owner: string, name: string): Promise<SSHKey> {
    return this.http.request('GET', keyPath(scope, owner, name));
  }

  /** DELETE /xkms/v1/ssh/keys/{scope}/{owner}/{name} (204). */
  async deleteKey(scope: string, owner: string, name: string): Promise<void> {
    await this.http.request<void>('DELETE', keyPath(scope, owner, name), { parse: 'void' });
  }

  /** GET /xkms/v1/ssh/keys/{scope}/{owner}/{name}/public */
  exportPublic(scope: string, owner: string, name: string): Promise<SSHPublicKey> {
    return this.http.request('GET', keyPath(scope, owner, name, '/public'));
  }

  /** POST /xkms/v1/ssh/keys/{scope}/{owner}/{name}/sign */
  sign(scope: string, owner: string, name: string, req: SSHSignRequest): Promise<SSHSignResponse> {
    return this.http.request('POST', keyPath(scope, owner, name, '/sign'), { body: req });
  }

  // ------------------------------------------------------------------
  // Known hosts
  // ------------------------------------------------------------------

  /** POST /xkms/v1/ssh/known-hosts (201). */
  async addKnownHost(req: SSHAddKnownHostRequest): Promise<void> {
    await this.http.request<void>('POST', `${BASE}/known-hosts`, {
      body: req,
      parse: 'void',
    });
  }

  /** GET /xkms/v1/ssh/known-hosts?scope=&owner= */
  listKnownHosts(scope?: string, owner?: string): Promise<SSHPinListResponse> {
    return this.http.request('GET', `${BASE}/known-hosts`, { query: { scope, owner } });
  }

  /** DELETE /xkms/v1/ssh/known-hosts/{host}?scope=&owner= (204). */
  async removeKnownHost(host: string, scope?: string, owner?: string): Promise<void> {
    await this.http.request<void>('DELETE', `${BASE}/known-hosts/${encodePathSegment(host)}`, {
      query: { scope, owner },
      parse: 'void',
    });
  }

  /**
   * POST /xkms/v1/ssh/known-hosts/{host}/verify — resolves on match (204);
   * a mismatch surfaces as an XkmsApiError with status 409 whose envelope
   * carries expected/received fingerprints.
   */
  async verifyKnownHost(host: string, req: SSHVerifyKnownHostRequest): Promise<void> {
    await this.http.request<void>(
      'POST',
      `${BASE}/known-hosts/${encodePathSegment(host)}/verify`,
      { body: req, parse: 'void' },
    );
  }

  // ------------------------------------------------------------------
  // Authorized keys
  // ------------------------------------------------------------------

  /** POST /xkms/v1/ssh/authorized-keys (201). */
  async addAuthorizedKey(req: SSHAddAuthorizedKeyRequest): Promise<void> {
    await this.http.request<void>('POST', `${BASE}/authorized-keys`, {
      body: req,
      parse: 'void',
    });
  }

  /** GET /xkms/v1/ssh/authorized-keys?scope=&owner= */
  listAuthorizedKeys(scope?: string, owner?: string): Promise<SSHAuthorizedListResponse> {
    return this.http.request('GET', `${BASE}/authorized-keys`, { query: { scope, owner } });
  }

  /** GET /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name} */
  getAuthorizedKey(scope: string, owner: string, name: string): Promise<SSHAuthorizedEntry> {
    return this.http.request('GET', authorizedPath(scope, owner, name));
  }

  /** DELETE /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name} (204). */
  async removeAuthorizedKey(scope: string, owner: string, name: string): Promise<void> {
    await this.http.request<void>('DELETE', authorizedPath(scope, owner, name), {
      parse: 'void',
    });
  }

  /** POST /xkms/v1/ssh/authorized-keys/emit */
  emitAuthorizedKey(req: SSHEmitRequest): Promise<SSHEmitResponse> {
    return this.http.request('POST', `${BASE}/authorized-keys/emit`, { body: req });
  }

  /** POST /xkms/v1/ssh/authorized-keys/verify — returns the matching entry. */
  verifyAuthorizedKey(req: SSHVerifyAuthorizedRequest): Promise<SSHAuthorizedEntry> {
    return this.http.request('POST', `${BASE}/authorized-keys/verify`, { body: req });
  }
}
