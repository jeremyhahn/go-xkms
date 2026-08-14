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

import { b64ToText, textToB64 } from "./b64.ts";

// PEM helpers for the CA and certificate screens.
//
// The REST DTOs carry PEM in fields typed Base64 because Go marshals a []byte
// that way — so a "certificate_pem" arrives base64-of-PEM, not PEM. Decoding
// it is required before display or download, and getting this wrong shows the
// operator a wall of base64 that looks like a corrupt certificate.

/**
 * decodePEM turns a base64-encoded PEM field into PEM text. A value that is
 * already PEM (some handlers return it unencoded) passes through unchanged, so
 * callers do not have to know which form they were given.
 */
export function decodePEM(value: string): string {
  if (value === "") return "";
  if (value.includes("-----BEGIN")) return value;
  try {
    const decoded = b64ToText(value);
    return decoded.includes("-----BEGIN") ? decoded : value;
  } catch {
    return value;
  }
}

/** encodePEM prepares PEM text for a Base64-typed request field. */
export function encodePEM(pem: string): string {
  return textToB64(pem.trim());
}

/**
 * downloadText offers text to the operator as a file. Certificates, chains and
 * CRLs are routinely pasted into other tools, and a download is less lossy than
 * a clipboard copy for multi-kilobyte PEM.
 */
export function downloadText(filename: string, text: string, mime = "application/x-pem-file"): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on the next task so the click has already been dispatched.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * RFC 5280 CRL reason codes. Revoking without a reason records
 * "unspecified" (0), which is legal but tells a future auditor nothing —
 * "keyCompromise" versus "superseded" changes how a relying party should treat
 * every certificate that key ever signed.
 *
 * 7 is not assigned; the list follows the RFC's numbering exactly.
 */
export const REVOCATION_REASONS: ReadonlyArray<{ value: number; label: string }> = [
  { value: 0, label: "unspecified" },
  { value: 1, label: "keyCompromise" },
  { value: 2, label: "cACompromise" },
  { value: 3, label: "affiliationChanged" },
  { value: 4, label: "superseded" },
  { value: 5, label: "cessationOfOperation" },
  { value: 6, label: "certificateHold" },
  { value: 8, label: "removeFromCRL" },
  { value: 9, label: "privilegeWithdrawn" },
  { value: 10, label: "aACompromise" },
];

/** reasonLabel maps a CRL reason code to its RFC 5280 name. */
export function reasonLabel(code: number | undefined): string {
  if (code === undefined) return "unspecified";
  return REVOCATION_REASONS.find((r) => r.value === code)?.label ?? `reason ${code}`;
}
