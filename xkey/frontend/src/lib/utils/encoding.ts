// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

/**
 * Encoding and clipboard utilities for the Keys view.
 */

/** Convert raw text to standard base64. */
export function textToBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

/** Decode standard base64 to a UTF-8 string. */
export function base64ToText(b64: string): string {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

/** Convert standard base64 to a hex string. */
export function base64ToHex(b64: string): string {
  const binary = atob(b64);
  let hex = '';
  for (let i = 0; i < binary.length; i++) {
    hex += binary.charCodeAt(i).toString(16).padStart(2, '0');
  }
  return hex;
}

/** Convert a hex string to standard base64. */
export function hexToBase64(hexStr: string): string {
  const clean = hexStr.replace(/\s/g, '');
  let binary = '';
  for (let i = 0; i < clean.length; i += 2) {
    binary += String.fromCharCode(parseInt(clean.substring(i, i + 2), 16));
  }
  return btoa(binary);
}

/** Copy text to clipboard with a notification. Uses navigator.clipboard API. */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
