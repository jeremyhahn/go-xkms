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

// Base64 helpers for the crypto panels. Every binary field on the xkms REST
// API is standard base64 (not base64url), matching Go's encoding/base64
// StdEncoding, which is what json.Marshal emits for a []byte.

/** bytesToB64 encodes raw bytes as standard base64. */
export function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  // Chunked so a large buffer cannot blow the argument limit of String
  // .fromCharCode via spread.
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}

/** b64ToBytes decodes standard base64 to raw bytes. Throws on invalid input. */
export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** textToB64 encodes a UTF-8 string as standard base64. */
export function textToB64(text: string): string {
  return bytesToB64(new TextEncoder().encode(text));
}

/**
 * b64ToText decodes base64 to a UTF-8 string. Binary that is not valid UTF-8
 * decodes to replacement characters rather than throwing, so callers can show
 * the raw base64 alongside and let the operator judge.
 */
export function b64ToText(b64: string): string {
  return new TextDecoder().decode(b64ToBytes(b64));
}

/** randomB64 returns n cryptographically random bytes as base64. */
export function randomB64(n: number): string {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return bytesToB64(buf);
}

/**
 * isB64 reports whether s parses as standard base64. Used to validate operator
 * input before a request, so a typo surfaces as a field error rather than a
 * 400 from the server.
 */
export function isB64(s: string): boolean {
  const t = s.trim();
  if (t === "") return false;
  try {
    atob(t);
    return true;
  } catch {
    return false;
  }
}

/**
 * b64Bytes returns the decoded byte length of a base64 string, or -1 when it
 * does not parse. Panels show it so an operator can confirm a nonce or tag is
 * the size the algorithm expects.
 */
export function b64Bytes(s: string): number {
  try {
    return b64ToBytes(s).length;
  } catch {
    return -1;
  }
}
