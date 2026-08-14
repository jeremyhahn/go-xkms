/**
 * webauthn.test.ts
 *
 * Unit tests for the shared WebAuthn serialisation helper (src/webauthn.ts),
 * ported from the quicbaas frontend bridge tests. These guard the two bug
 * classes the helper exists to prevent:
 *
 *   1. Envelope leak — the server returns { publicKey: { challenge, ... } };
 *      passing it straight to navigator.credentials.create()/get() leaves
 *      challenge undefined. parseCreationOptions / parseRequestOptions must
 *      unwrap it.
 *   2. Binary encoding — challenge / id members are base64url strings on the
 *      wire and must become ArrayBuffers for the API, and the credential the
 *      API returns must be re-encoded as base64url under go-webauthn camelCase
 *      keys (rawId / attestationObject / clientDataJSON / authenticatorData /
 *      signature / userHandle) — NOT number[] arrays, NOT snake_case.
 */

import { describe, it, expect } from 'vitest';
import {
  base64urlToBuffer,
  bufferToBase64url,
  parseCreationOptions,
  parseRequestOptions,
  encodeAttestationResponse,
  encodeAssertionResponse,
  WebAuthnEnvelopeError,
} from './webauthn.js';

// ---------------------------------------------------------------------------
// base64url round-trip
// ---------------------------------------------------------------------------

describe('base64url <-> ArrayBuffer', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const encoded = bufferToBase64url(bytes.buffer);
    const decoded = new Uint8Array(base64urlToBuffer(encoded));
    expect(Array.from(decoded)).toEqual(Array.from(bytes));
  });

  it('emits unpadded base64url (no +, /, or =)', () => {
    // 0xFB 0xFF would be "+/" / "=" in standard base64 padded form.
    const encoded = bufferToBase64url(new Uint8Array([0xfb, 0xff, 0xfe]).buffer);
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it('decodes the canonical go-webauthn RawURLEncoding form', () => {
    // "AQID" is base64 for [1,2,3]; RawURLEncoding drops padding.
    const decoded = new Uint8Array(base64urlToBuffer('AQID'));
    expect(Array.from(decoded)).toEqual([1, 2, 3]);
  });

  it('tolerates standard base64 input (+/ and = padding)', () => {
    const decoded = new Uint8Array(base64urlToBuffer('+/8='));
    expect(Array.from(decoded)).toEqual([0xfb, 0xff]);
  });

  it('accepts an ArrayBufferView (e.g. Uint8Array) directly', () => {
    const view = new Uint8Array([10, 20, 30]);
    expect(bufferToBase64url(view)).toBe(bufferToBase64url(view.buffer));
  });
});

// ---------------------------------------------------------------------------
// parseCreationOptions
// ---------------------------------------------------------------------------

describe('parseCreationOptions', () => {
  // Mirrors the live server envelope captured in the bug report.
  const envelope = {
    publicKey: {
      attestation: 'none',
      authenticatorSelection: { userVerification: 'preferred' },
      challenge: 'AQID',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      rp: { id: 'localhost', name: 'xkms' },
      timeout: 60000,
      user: { displayName: 'Alice', id: 'BAUG', name: 'alice' },
      excludeCredentials: [{ type: 'public-key', id: 'BwgJ' }],
    },
  };

  it('unwraps the publicKey envelope and decodes binary members', () => {
    const opts = parseCreationOptions(envelope);
    expect(opts.challenge).toBeInstanceOf(ArrayBuffer);
    expect(Array.from(new Uint8Array(opts.challenge as ArrayBuffer))).toEqual([1, 2, 3]);
    expect(opts.user.id).toBeInstanceOf(ArrayBuffer);
    expect(Array.from(new Uint8Array(opts.user.id as ArrayBuffer))).toEqual([4, 5, 6]);
    expect(opts.excludeCredentials?.[0]?.id).toBeInstanceOf(ArrayBuffer);
    expect(
      Array.from(new Uint8Array(opts.excludeCredentials![0]!.id as ArrayBuffer)),
    ).toEqual([7, 8, 9]);
  });

  it('preserves non-binary scalar fields verbatim', () => {
    const opts = parseCreationOptions(envelope);
    expect(opts.rp.id).toBe('localhost');
    expect(opts.timeout).toBe(60000);
    expect(opts.attestation).toBe('none');
    expect(opts.user.name).toBe('alice');
  });

  it('tolerates an already-unwrapped (top-level challenge) shape', () => {
    const opts = parseCreationOptions(envelope.publicKey);
    expect(opts.challenge).toBeInstanceOf(ArrayBuffer);
  });

  it('throws WebAuthnEnvelopeError when publicKey/challenge is missing', () => {
    // This is the exact failure the original bug produced: the envelope was
    // never unwrapped so challenge was undefined.
    expect(() => parseCreationOptions({ foo: 'bar' })).toThrow(WebAuthnEnvelopeError);
    expect(() => parseCreationOptions({ publicKey: { user: {} } })).toThrow(
      WebAuthnEnvelopeError,
    );
    expect(() => parseCreationOptions(null)).toThrow(WebAuthnEnvelopeError);
  });
});

// ---------------------------------------------------------------------------
// parseRequestOptions
// ---------------------------------------------------------------------------

describe('parseRequestOptions', () => {
  const envelope = {
    publicKey: {
      challenge: 'AQID',
      timeout: 60000,
      rpId: 'localhost',
      userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: 'BAUG', transports: ['internal'] }],
    },
  };

  it('unwraps the envelope and decodes challenge + allowCredentials', () => {
    const opts = parseRequestOptions(envelope);
    expect(opts.challenge).toBeInstanceOf(ArrayBuffer);
    expect(Array.from(new Uint8Array(opts.challenge as ArrayBuffer))).toEqual([1, 2, 3]);
    expect(opts.allowCredentials?.[0]?.id).toBeInstanceOf(ArrayBuffer);
    expect(opts.allowCredentials?.[0]?.transports).toEqual(['internal']);
    expect(opts.rpId).toBe('localhost');
    expect(opts.userVerification).toBe('required');
  });

  it('throws WebAuthnEnvelopeError when challenge is missing', () => {
    expect(() => parseRequestOptions({ publicKey: {} })).toThrow(WebAuthnEnvelopeError);
  });
});

// ---------------------------------------------------------------------------
// encodeAttestationResponse / encodeAssertionResponse
// ---------------------------------------------------------------------------

function bufOf(bytes: number[]): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

describe('encodeAttestationResponse', () => {
  it('emits go-webauthn camelCase base64url JSON for registration', () => {
    const cred = {
      id: 'cred-id',
      rawId: bufOf([1, 2, 3]),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: bufOf([4, 5, 6]),
        attestationObject: bufOf([7, 8, 9]),
        getTransports: () => ['internal', 'hybrid'],
      },
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    } as unknown as PublicKeyCredential;

    const out = encodeAttestationResponse(cred);
    expect(out).toMatchObject({
      id: 'cred-id',
      rawId: bufferToBase64url(bufOf([1, 2, 3])),
      type: 'public-key',
      authenticatorAttachment: 'platform',
    });
    expect(out.response.clientDataJSON).toBe(bufferToBase64url(bufOf([4, 5, 6])));
    expect(out.response.attestationObject).toBe(bufferToBase64url(bufOf([7, 8, 9])));
    expect(out.response.transports).toEqual(['internal', 'hybrid']);
    // No number[] arrays and no snake_case keys leak through.
    expect(JSON.stringify(out)).not.toMatch(/raw_id|attestation_object|client_data_json/);
  });

  it('omits transports when the authenticator reports none', () => {
    const cred = {
      id: 'c',
      rawId: bufOf([1]),
      type: 'public-key',
      response: {
        clientDataJSON: bufOf([2]),
        attestationObject: bufOf([3]),
        getTransports: () => [],
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;
    const out = encodeAttestationResponse(cred);
    expect(out.response.transports).toBeUndefined();
  });
});

describe('encodeAssertionResponse', () => {
  it('emits go-webauthn camelCase base64url JSON for login', () => {
    const cred = {
      id: 'cred-id',
      rawId: bufOf([1, 2, 3]),
      type: 'public-key',
      response: {
        clientDataJSON: bufOf([4]),
        authenticatorData: bufOf([5]),
        signature: bufOf([6]),
        userHandle: bufOf([7]),
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;

    const out = encodeAssertionResponse(cred);
    expect(out.rawId).toBe(bufferToBase64url(bufOf([1, 2, 3])));
    expect(out.response.authenticatorData).toBe(bufferToBase64url(bufOf([5])));
    expect(out.response.signature).toBe(bufferToBase64url(bufOf([6])));
    expect(out.response.userHandle).toBe(bufferToBase64url(bufOf([7])));
  });

  it('includes authenticatorAttachment when the authenticator reports one', () => {
    const cred = {
      id: 'cred-id',
      rawId: bufOf([1]),
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
      response: {
        clientDataJSON: bufOf([2]),
        authenticatorData: bufOf([3]),
        signature: bufOf([4]),
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;
    const out = encodeAssertionResponse(cred);
    expect(out.authenticatorAttachment).toBe('cross-platform');
  });

  it('omits userHandle when absent (non-discoverable credential)', () => {
    const cred = {
      id: 'c',
      rawId: bufOf([1]),
      type: 'public-key',
      response: {
        clientDataJSON: bufOf([2]),
        authenticatorData: bufOf([3]),
        signature: bufOf([4]),
        userHandle: null,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;
    const out = encodeAssertionResponse(cred);
    expect(out.response.userHandle).toBeUndefined();
  });
});
