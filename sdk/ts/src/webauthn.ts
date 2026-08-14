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

/**
 * Shared WebAuthn (FIDO2) serialisation helpers.
 *
 * The browser's Web Authentication API speaks BufferSource (ArrayBuffer /
 * TypedArray) for every binary member, while the xkms server speaks
 * base64url-encoded JSON strings. The server side is the go-webauthn library
 * (github.com/go-webauthn/webauthn), whose wire types decode binary members
 * with base64.RawURLEncoding and whose challenge options are wrapped in a
 * top-level `publicKey` envelope (CredentialCreation / CredentialAssertion).
 *
 * This module is the SINGLE place that bridges the two representations. Every
 * view that calls navigator.credentials.create()/get() must route through it
 * so there is exactly one correct encode/decode implementation.
 *
 * Two classes of bug this module exists to prevent:
 *
 *   1. Envelope leak — the server returns `{ "publicKey": { challenge, ... } }`.
 *      Passing that object straight to navigator.credentials.create() leaves
 *      options.publicKey.challenge undefined (the real challenge is one level
 *      deeper), so the browser throws:
 *        "Failed to read the 'challenge' property ... Required member is undefined."
 *      parseCreationOptions / parseRequestOptions unwrap the envelope.
 *
 *   2. Binary encoding — challenge, user.id, allowCredentials[].id,
 *      excludeCredentials[].id are base64url strings on the wire but must be
 *      ArrayBuffers for the API; the credential the API returns has ArrayBuffer
 *      members that must be re-encoded as base64url strings for the finish call.
 *      The encoded field names match go-webauthn exactly (rawId,
 *      attestationObject, clientDataJSON, authenticatorData, signature,
 *      userHandle) — NOT snake_case and NOT number[] arrays.
 */

// ---------------------------------------------------------------------------
// base64url <-> ArrayBuffer
// ---------------------------------------------------------------------------

/**
 * base64urlToBuffer decodes a base64url (RFC 4648 §5, unpadded) string into an
 * ArrayBuffer. Standard base64 (with +/ and = padding) is also accepted so the
 * helper is tolerant of either server emission.
 */
export function base64urlToBuffer(value: string): ArrayBuffer {
  const normalised = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * bufferToBase64url encodes an ArrayBuffer (or ArrayBufferView) into an
 * unpadded base64url string, the form go-webauthn's URLEncodedBase64 decoder
 * (base64.RawURLEncoding) expects.
 */
export function bufferToBase64url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * WebAuthnEnvelopeError is thrown when the server's challenge options are not
 * in the expected go-webauthn `{ publicKey: { challenge, ... } }` shape (or the
 * already-unwrapped shape with a top-level challenge). It signals a transport
 * or version mismatch rather than a user-cancel, so callers can surface a
 * distinct message.
 */
export class WebAuthnEnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebAuthnEnvelopeError';
  }
}

// ---------------------------------------------------------------------------
// Internal shapes (the JSON the server emits / accepts)
// ---------------------------------------------------------------------------

interface CredentialDescriptorJSON {
  id: string;
  type: 'public-key';
  transports?: AuthenticatorTransport[];
}

// The inner go-webauthn PublicKeyCredentialCreationOptions JSON, where binary
// members are base64url strings.
interface CreationOptionsJSON {
  challenge: string;
  rp: PublicKeyCredentialRpEntity;
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: CredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: AuthenticationExtensionsClientInputs;
}

// The inner go-webauthn PublicKeyCredentialRequestOptions JSON.
interface RequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: CredentialDescriptorJSON[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
}

// ---------------------------------------------------------------------------
// Envelope unwrap
// ---------------------------------------------------------------------------

/**
 * unwrapEnvelope returns the inner options object. go-webauthn wraps both
 * creation and request options in a top-level `publicKey` key
 * (CredentialCreation / CredentialAssertion). A server that ever returns the
 * already-unwrapped object (top-level `challenge`) is also tolerated.
 */
function unwrapEnvelope(raw: unknown): Record<string, unknown> {
  if (raw === null || typeof raw !== 'object') {
    throw new WebAuthnEnvelopeError('WebAuthn options missing from server response');
  }
  const obj = raw as Record<string, unknown>;
  const inner =
    obj.publicKey !== undefined && obj.publicKey !== null
      ? (obj.publicKey as Record<string, unknown>)
      : obj;
  if (typeof inner.challenge !== 'string' || inner.challenge.length === 0) {
    throw new WebAuthnEnvelopeError(
      'WebAuthn challenge missing from server response (unexpected options shape)',
    );
  }
  return inner;
}

// ---------------------------------------------------------------------------
// Parse server options -> browser PublicKeyCredential*Options
// ---------------------------------------------------------------------------

/**
 * parseCreationOptions unwraps the server's registration challenge envelope and
 * decodes its binary members (challenge, user.id, excludeCredentials[].id) into
 * ArrayBuffers so the result can be passed directly to
 * navigator.credentials.create({ publicKey }).
 */
export function parseCreationOptions(raw: unknown): PublicKeyCredentialCreationOptions {
  const json = unwrapEnvelope(raw) as unknown as CreationOptionsJSON;
  const options: PublicKeyCredentialCreationOptions = {
    challenge: base64urlToBuffer(json.challenge),
    rp: json.rp,
    user: {
      id: base64urlToBuffer(json.user.id),
      name: json.user.name,
      displayName: json.user.displayName,
    },
    pubKeyCredParams: json.pubKeyCredParams,
  };
  if (json.timeout !== undefined) options.timeout = json.timeout;
  if (json.attestation !== undefined) options.attestation = json.attestation;
  if (json.authenticatorSelection !== undefined) {
    options.authenticatorSelection = json.authenticatorSelection;
  }
  if (json.extensions !== undefined) options.extensions = json.extensions;
  if (json.excludeCredentials !== undefined) {
    options.excludeCredentials = json.excludeCredentials.map((c) => ({
      id: base64urlToBuffer(c.id),
      type: c.type,
      ...(c.transports !== undefined ? { transports: c.transports } : {}),
    }));
  }
  return options;
}

/**
 * parseRequestOptions unwraps the server's login challenge envelope and decodes
 * its binary members (challenge, allowCredentials[].id) into ArrayBuffers so the
 * result can be passed directly to navigator.credentials.get({ publicKey }).
 */
export function parseRequestOptions(raw: unknown): PublicKeyCredentialRequestOptions {
  const json = unwrapEnvelope(raw) as unknown as RequestOptionsJSON;
  const options: PublicKeyCredentialRequestOptions = {
    challenge: base64urlToBuffer(json.challenge),
  };
  if (json.timeout !== undefined) options.timeout = json.timeout;
  if (json.rpId !== undefined) options.rpId = json.rpId;
  if (json.userVerification !== undefined) options.userVerification = json.userVerification;
  if (json.extensions !== undefined) options.extensions = json.extensions;
  if (json.allowCredentials !== undefined) {
    options.allowCredentials = json.allowCredentials.map((c) => ({
      id: base64urlToBuffer(c.id),
      type: c.type,
      ...(c.transports !== undefined ? { transports: c.transports } : {}),
    }));
  }
  return options;
}

// ---------------------------------------------------------------------------
// Encode browser credential -> server JSON (go-webauthn shape)
// ---------------------------------------------------------------------------

/**
 * AttestationCredentialJSON is the registration response shape go-webauthn's
 * ParseCredentialCreationResponseBytes expects: base64url string members under
 * camelCase keys.
 */
export interface AttestationCredentialJSON {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
  };
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

/**
 * AssertionCredentialJSON is the login response shape go-webauthn's
 * ParseCredentialRequestResponseBytes expects.
 */
export interface AssertionCredentialJSON {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

/**
 * encodeAttestationResponse serialises the PublicKeyCredential returned by
 * navigator.credentials.create() into the base64url JSON go-webauthn parses.
 * When the authenticator reports transports they are included (go-webauthn
 * reads response.transports).
 */
export function encodeAttestationResponse(
  credential: PublicKeyCredential,
): AttestationCredentialJSON {
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports =
    typeof response.getTransports === 'function' ? response.getTransports() : [];
  const out: AttestationCredentialJSON = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if (credential.authenticatorAttachment) {
    out.authenticatorAttachment = credential.authenticatorAttachment;
  }
  if (transports.length > 0) {
    out.response.transports = transports;
  }
  return out;
}

/**
 * encodeAssertionResponse serialises the PublicKeyCredential returned by
 * navigator.credentials.get() into the base64url JSON go-webauthn parses.
 * userHandle is included only when the authenticator returned one
 * (discoverable-credential flow).
 */
export function encodeAssertionResponse(
  credential: PublicKeyCredential,
): AssertionCredentialJSON {
  const response = credential.response as AuthenticatorAssertionResponse;
  const out: AssertionCredentialJSON = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if (credential.authenticatorAttachment) {
    out.authenticatorAttachment = credential.authenticatorAttachment;
  }
  if (response.userHandle && response.userHandle.byteLength > 0) {
    out.response.userHandle = bufferToBase64url(response.userHandle);
  }
  return out;
}
