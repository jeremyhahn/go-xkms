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

/**
 * CredentialProvider — the seam that lets LoginPanel / RegisterPanel run the
 * same ceremony against different credential sources. The browser provider
 * drives navigator.credentials + the SDK's WebAuthn wire bridge; a desktop
 * shell (Wails, Electron) injects its own provider that talks to local
 * hardware (FIDO2 CTAP2, PIV) instead.
 */

import {
  parseCreationOptions,
  parseRequestOptions,
  encodeAssertionResponse,
  encodeAttestationResponse,
  type AssertionCredentialJSON,
  type AttestationCredentialJSON,
  type TokenResponse,
} from '@go-xkms/sdk';

import type { AuthClientHost } from './config.ts';

/** Authentication methods a provider can offer. */
export type AuthMethod = 'passkey' | 'certificate';

/** The access/refresh pair a certificate login yields. */
export type TokenPairResponse = TokenResponse;

/**
 * CredentialCeremonyError is thrown when the authenticator ceremony ends
 * without a credential — the user declined, cancelled, or timed out.
 */
export class CredentialCeremonyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialCeremonyError';
  }
}

/** CredentialProvider supplies credentials for the login/register ceremonies. */
export interface CredentialProvider {
  /** The methods this provider can perform right now. */
  methods(): Promise<AuthMethod[]>;
  /**
   * Run the assertion (login) ceremony for the server's raw request-options
   * envelope and return the encoded go-webauthn JSON.
   */
  getAssertion(options: unknown): Promise<AssertionCredentialJSON>;
  /**
   * Run the attestation (registration) ceremony for the server's raw
   * creation-options envelope and return the encoded go-webauthn JSON.
   */
  createCredential(options: unknown): Promise<AttestationCredentialJSON>;
  /** Exchange a client certificate (PIV / mTLS) for a bearer token pair. */
  loginCertificate(): Promise<TokenPairResponse>;
}

/**
 * BrowserCredentialProvider is the default web implementation:
 * navigator.credentials for the WebAuthn ceremonies and the SDK's loginCert
 * (TLS client certificate, credentials:'include') for the certificate path.
 *
 * methods() reports what this CLIENT can perform, not what the server accepts.
 * A browser can always attempt either ceremony, so both are listed; LoginPanel
 * intersects this with the deployment's /api/v1/capabilities so a method the
 * server has disabled is never offered.
 */
export class BrowserCredentialProvider implements CredentialProvider {
  constructor(private readonly client: AuthClientHost) {}

  async methods(): Promise<AuthMethod[]> {
    return ['passkey', 'certificate'];
  }

  async getAssertion(options: unknown): Promise<AssertionCredentialJSON> {
    const publicKey = parseRequestOptions(options);
    const credential = await navigator.credentials.get({ publicKey });
    if (credential === null) {
      throw new CredentialCeremonyError('authentication was declined or cancelled');
    }
    return encodeAssertionResponse(credential as PublicKeyCredential);
  }

  async createCredential(options: unknown): Promise<AttestationCredentialJSON> {
    const publicKey = parseCreationOptions(options);
    const credential = await navigator.credentials.create({ publicKey });
    if (credential === null) {
      throw new CredentialCeremonyError('credential creation was declined or cancelled');
    }
    return encodeAttestationResponse(credential as PublicKeyCredential);
  }

  loginCertificate(): Promise<TokenPairResponse> {
    return this.client.auth.loginCert();
  }
}

/**
 * isUserDeclined reports whether an error means the user (or authenticator)
 * declined/cancelled the ceremony rather than the server rejecting it.
 */
export function isUserDeclined(err: unknown): boolean {
  if (err instanceof CredentialCeremonyError) return true;
  return (
    err instanceof DOMException &&
    (err.name === 'NotAllowedError' || err.name === 'AbortError')
  );
}

/**
 * isNetworkFailure reports whether an error is a transport problem (server
 * unreachable) rather than an answer from the server.
 */
export function isNetworkFailure(err: unknown): boolean {
  if (err instanceof TypeError) return true;
  return (err as { name?: string }).name === 'XkmsNetworkError';
}
