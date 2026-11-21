// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

import type { HttpCore } from '../http.js';
import type { AttestationCredentialJSON } from '../webauthn.js';
import type { WebAuthnCeremonyStart } from '../types/auth.js';

/** Mirrors pkg/api/transport/types.go GetInviteResponse. */
export interface InviteInfo {
  email?: string;
  display_name?: string;
  expires_at: string;
  /** Credential kinds this build can activate the invite with ("webauthn", "piv"). */
  methods: string[];
}

/** Mirrors pkg/api/transport/types.go FinishInviteRegistrationResponse. */
export interface InviteRegistrationResult {
  user_id: string;
}

interface BeginInviteRegistrationResponse {
  session_id: string;
  options_json: string;
}

const INVITES_BASE = '/api/v1/invites';

/**
 * Public invite redemption (pkg/api/rest/handlers_invite.go). Every call is
 * unauthenticated: the single-use token in the path is the credential. An
 * unusable link (unknown, spent, expired, wrong tenant) answers 404.
 */
export class InvitesClient {
  constructor(private readonly http: HttpCore) {}

  private path(tenant: string, token: string, suffix = ''): string {
    return `${INVITES_BASE}/${encodeURIComponent(tenant)}/${encodeURIComponent(token)}${suffix}`;
  }

  /** GET /api/v1/invites/{tenant}/{token} */
  get(tenant: string, token: string): Promise<InviteInfo> {
    return this.http.request('GET', this.path(tenant, token), { auth: false });
  }

  /**
   * POST /api/v1/invites/{tenant}/{token}/fido2/begin. Returns the creation
   * options envelope (the same shape the self-service registration begin
   * returns) for a CredentialProvider.createCredential call.
   */
  async beginRegistration(tenant: string, token: string): Promise<WebAuthnCeremonyStart> {
    const resp = await this.http.request<BeginInviteRegistrationResponse>(
      'POST',
      this.path(tenant, token, '/fido2/begin'),
      { auth: false, body: {} },
    );
    return { sessionId: resp.session_id, options: JSON.parse(resp.options_json) as unknown };
  }

  /** POST /api/v1/invites/{tenant}/{token}/fido2/finish */
  finishRegistration(
    tenant: string,
    token: string,
    sessionId: string,
    credential: AttestationCredentialJSON,
  ): Promise<InviteRegistrationResult> {
    return this.http.request('POST', this.path(tenant, token, '/fido2/finish'), {
      auth: false,
      body: { session_id: sessionId, attestation_json: JSON.stringify(credential) },
    });
  }
}
