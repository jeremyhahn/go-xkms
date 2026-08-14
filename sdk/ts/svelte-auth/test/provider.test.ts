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
 * BrowserCredentialProvider tests: delegation to navigator.credentials, the
 * SDK wire-bridge round trip (base64url envelope -> ArrayBuffer -> base64url
 * JSON), decline handling, and certificate-login delegation.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { base64urlToBuffer, bufferToBase64url } from '@go-xkms/sdk';

import {
  BrowserCredentialProvider,
  CredentialCeremonyError,
  isNetworkFailure,
  isUserDeclined,
} from '../src/provider.ts';
import { FakeApiError, makeFakeClient, tokenPair } from './helpers.ts';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** base64url-encode a UTF-8 string. */
function b64u(value: string): string {
  return bufferToBase64url(encoder.encode(value));
}

/** Decode an ArrayBuffer(-view) back to a UTF-8 string. */
function text(buffer: ArrayBuffer | ArrayBufferView): string {
  return decoder.decode(
    buffer instanceof ArrayBuffer
      ? buffer
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength),
  );
}

// The stubs hand the encoder Uint8Array VIEWS (not bare ArrayBuffers): under
// vitest's jsdom environment ArrayBuffers can cross realms, which breaks
// `instanceof ArrayBuffer` checks, while views are handled structurally.

/** A navigator.credentials.get() result stub (assertion). */
function assertionCredential(): PublicKeyCredential {
  return {
    id: 'cred-id',
    rawId: encoder.encode('cred-id'),
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: encoder.encode('client-data'),
      authenticatorData: encoder.encode('auth-data'),
      signature: encoder.encode('sig'),
      userHandle: encoder.encode('user-1'),
    },
    getClientExtensionResults: () => ({}),
  } as unknown as PublicKeyCredential;
}

/** A navigator.credentials.create() result stub (attestation). */
function attestationCredential(): PublicKeyCredential {
  return {
    id: 'new-cred',
    rawId: encoder.encode('new-cred'),
    type: 'public-key',
    authenticatorAttachment: 'cross-platform',
    response: {
      clientDataJSON: encoder.encode('client-data'),
      attestationObject: encoder.encode('att-obj'),
      getTransports: () => ['usb'],
    },
    getClientExtensionResults: () => ({}),
  } as unknown as PublicKeyCredential;
}

describe('BrowserCredentialProvider', () => {
  const credentialsGet = vi.fn();
  const credentialsCreate = vi.fn();

  beforeEach(() => {
    credentialsGet.mockReset();
    credentialsCreate.mockReset();
    Object.defineProperty(window.navigator, 'credentials', {
      configurable: true,
      value: { get: credentialsGet, create: credentialsCreate },
    });
  });

  it('offers both passkey and certificate in the browser', async () => {
    const { client } = makeFakeClient();
    const provider = new BrowserCredentialProvider(client);

    await expect(provider.methods()).resolves.toEqual(['passkey', 'certificate']);
  });

  // -------------------------------------------------------------------------
  // getAssertion
  // -------------------------------------------------------------------------

  it('decodes the request envelope, calls navigator.credentials.get, and re-encodes', async () => {
    const { client } = makeFakeClient();
    const provider = new BrowserCredentialProvider(client);
    credentialsGet.mockResolvedValue(assertionCredential());

    const envelope = {
      publicKey: {
        challenge: b64u('login-challenge'),
        rpId: 'localhost',
        allowCredentials: [{ id: b64u('allowed-cred'), type: 'public-key' }],
      },
    };

    const json = await provider.getAssertion(envelope);

    // The browser saw decoded ArrayBuffers, not base64url strings.
    expect(credentialsGet).toHaveBeenCalledTimes(1);
    const arg = credentialsGet.mock.calls[0]?.[0] as {
      publicKey: PublicKeyCredentialRequestOptions;
    };
    expect(text(arg.publicKey.challenge as ArrayBuffer)).toBe('login-challenge');
    expect(arg.publicKey.rpId).toBe('localhost');
    expect(text(arg.publicKey.allowCredentials?.[0]?.id as ArrayBuffer)).toBe(
      'allowed-cred',
    );

    // The wire JSON round-trips through the sdk bridge.
    expect(json.id).toBe('cred-id');
    expect(text(base64urlToBuffer(json.rawId))).toBe('cred-id');
    expect(text(base64urlToBuffer(json.response.signature))).toBe('sig');
    expect(text(base64urlToBuffer(json.response.authenticatorData))).toBe('auth-data');
    expect(text(base64urlToBuffer(json.response.clientDataJSON))).toBe('client-data');
    expect(json.response.userHandle).toBeDefined();
    expect(text(base64urlToBuffer(json.response.userHandle as string))).toBe('user-1');
  });

  it('throws CredentialCeremonyError when the assertion ceremony yields null', async () => {
    const { client } = makeFakeClient();
    const provider = new BrowserCredentialProvider(client);
    credentialsGet.mockResolvedValue(null);

    await expect(
      provider.getAssertion({ publicKey: { challenge: b64u('c') } }),
    ).rejects.toBeInstanceOf(CredentialCeremonyError);
  });

  // -------------------------------------------------------------------------
  // createCredential
  // -------------------------------------------------------------------------

  it('decodes the creation envelope, calls navigator.credentials.create, and re-encodes', async () => {
    const { client } = makeFakeClient();
    const provider = new BrowserCredentialProvider(client);
    credentialsCreate.mockResolvedValue(attestationCredential());

    const envelope = {
      publicKey: {
        challenge: b64u('reg-challenge'),
        rp: { id: 'localhost', name: 'xkms' },
        user: { id: b64u('user-1'), name: 'a@b.example', displayName: 'Jane' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
    };

    const json = await provider.createCredential(envelope);

    expect(credentialsCreate).toHaveBeenCalledTimes(1);
    const arg = credentialsCreate.mock.calls[0]?.[0] as {
      publicKey: PublicKeyCredentialCreationOptions;
    };
    expect(text(arg.publicKey.challenge as ArrayBuffer)).toBe('reg-challenge');
    expect(text(arg.publicKey.user.id as ArrayBuffer)).toBe('user-1');
    expect(arg.publicKey.rp.name).toBe('xkms');

    expect(json.id).toBe('new-cred');
    expect(text(base64urlToBuffer(json.rawId))).toBe('new-cred');
    expect(text(base64urlToBuffer(json.response.attestationObject))).toBe('att-obj');
    expect(json.response.transports).toEqual(['usb']);
    expect(json.authenticatorAttachment).toBe('cross-platform');
  });

  it('throws CredentialCeremonyError when the creation ceremony yields null', async () => {
    const { client } = makeFakeClient();
    const provider = new BrowserCredentialProvider(client);
    credentialsCreate.mockResolvedValue(null);

    await expect(
      provider.createCredential({
        publicKey: {
          challenge: b64u('c'),
          rp: { name: 'xkms' },
          user: { id: b64u('u'), name: 'n', displayName: 'd' },
          pubKeyCredParams: [],
        },
      }),
    ).rejects.toBeInstanceOf(CredentialCeremonyError);
  });

  it('rejects a malformed envelope without touching the authenticator', async () => {
    const { client } = makeFakeClient();
    const provider = new BrowserCredentialProvider(client);

    await expect(provider.getAssertion({ nope: true })).rejects.toThrow();
    expect(credentialsGet).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // loginCertificate
  // -------------------------------------------------------------------------

  it('delegates certificate login to the sdk loginCert exchange', async () => {
    const { client, mocks } = makeFakeClient();
    mocks.loginCert.mockResolvedValue(tokenPair('cert-acc', 'cert-ref'));
    const provider = new BrowserCredentialProvider(client);

    await expect(provider.loginCertificate()).resolves.toEqual(
      tokenPair('cert-acc', 'cert-ref'),
    );
    expect(mocks.loginCert).toHaveBeenCalledTimes(1);
  });

  // -------------------------------------------------------------------------
  // isUserDeclined
  // -------------------------------------------------------------------------

  it('recognizes a CredentialCeremonyError (null-credential ceremony result) as declined', () => {
    expect(isUserDeclined(new CredentialCeremonyError('cancelled'))).toBe(true);
  });

  it('recognizes NotAllowedError and AbortError DOMExceptions as declined', () => {
    expect(isUserDeclined(new DOMException('nope', 'NotAllowedError'))).toBe(true);
    expect(isUserDeclined(new DOMException('nope', 'AbortError'))).toBe(true);
  });

  it('does not classify a server rejection or an unrelated error as user-declined', () => {
    expect(isUserDeclined(new FakeApiError(401, 'invalid token'))).toBe(false);
    expect(isUserDeclined(new DOMException('nope', 'SecurityError'))).toBe(false);
    expect(isUserDeclined(new Error('boom'))).toBe(false);
    expect(isUserDeclined('not an error at all')).toBe(false);
  });

  // -------------------------------------------------------------------------
  // isNetworkFailure
  // -------------------------------------------------------------------------

  it('recognizes a TypeError (the SDK/fetch signature for a transport failure) as a network failure', () => {
    expect(isNetworkFailure(new TypeError('Failed to fetch'))).toBe(true);
  });

  it('recognizes an error named XkmsNetworkError as a network failure', () => {
    const err = new Error('server unreachable');
    err.name = 'XkmsNetworkError';
    expect(isNetworkFailure(err)).toBe(true);
  });

  it('does not classify a server-answered rejection as a network failure', () => {
    expect(isNetworkFailure(new FakeApiError(400, 'bad request'))).toBe(false);
    expect(isNetworkFailure(new Error('generic failure'))).toBe(false);
  });
});
