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

import { describe, it, expect } from "vitest";
import { decodePEM, encodePEM, REVOCATION_REASONS, reasonLabel } from "../src/lib/pem.ts";
import { textToB64 } from "../src/lib/b64.ts";

const PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";

// The REST DTOs type PEM fields as Base64 because Go marshals []byte that way,
// so "certificate_pem" arrives as base64-of-PEM. Rendering it without decoding
// shows the operator a wall of base64 that reads as a corrupt certificate.
describe("PEM helpers", () => {
  it("decodes a base64-wrapped PEM field", () => {
    expect(decodePEM(textToB64(PEM))).toBe(PEM);
  });

  it("passes through a field that is already PEM", () => {
    // Some handlers return PEM unencoded; callers should not have to know
    // which form they got.
    expect(decodePEM(PEM)).toBe(PEM);
  });

  it("returns the input unchanged when it is neither", () => {
    expect(decodePEM("garbage!!")).toBe("garbage!!");
    expect(decodePEM("")).toBe("");
  });

  it("does not mistake base64 that decodes to non-PEM for PEM", () => {
    const notPem = textToB64("just some text");
    expect(decodePEM(notPem)).toBe(notPem);
  });

  it("round-trips through encodePEM", () => {
    expect(decodePEM(encodePEM(PEM))).toBe(PEM);
  });

  it("covers the RFC 5280 reason codes, skipping the unassigned 7", () => {
    const codes = REVOCATION_REASONS.map((r) => r.value);
    expect(codes).toEqual([0, 1, 2, 3, 4, 5, 6, 8, 9, 10]);
    expect(codes).not.toContain(7);
  });

  it("names reason codes and degrades gracefully on an unknown one", () => {
    expect(reasonLabel(1)).toBe("keyCompromise");
    expect(reasonLabel(4)).toBe("superseded");
    expect(reasonLabel(undefined)).toBe("unspecified");
    expect(reasonLabel(99)).toBe("reason 99");
  });
});
