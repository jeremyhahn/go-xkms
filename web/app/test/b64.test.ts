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
import {
  bytesToB64,
  b64ToBytes,
  textToB64,
  b64ToText,
  randomB64,
  isB64,
  b64Bytes,
} from "../src/lib/b64.ts";

// Every binary field on the xkms REST API is standard base64 — the encoding
// Go's json.Marshal produces for a []byte. These pin that contract, because a
// silent mismatch here corrupts ciphertext, nonces, and wrapped key material
// in ways the server can only report as a generic decrypt failure.
describe("base64 helpers", () => {
  it("round-trips arbitrary bytes including NUL and high bytes", () => {
    const bytes = new Uint8Array([0, 1, 127, 128, 200, 254, 255]);
    expect(b64ToBytes(bytesToB64(bytes))).toEqual(bytes);
  });

  it("encodes with standard base64, not base64url", () => {
    // 0xFF 0xFE 0xFD encodes to "//79" in standard base64 and "_-79" in
    // base64url. The server decodes with StdEncoding, so '+' and '/' must
    // survive.
    expect(bytesToB64(new Uint8Array([0xff, 0xfe, 0xfd]))).toBe("//79");
    expect(bytesToB64(new Uint8Array([0xfb, 0xef, 0xbe]))).toContain("+");
  });

  it("pads to a multiple of four characters", () => {
    expect(bytesToB64(new Uint8Array([1]))).toBe("AQ==");
    expect(bytesToB64(new Uint8Array([1, 2]))).toBe("AQI=");
    expect(bytesToB64(new Uint8Array([1, 2, 3]))).toBe("AQID");
  });

  it("round-trips multi-byte UTF-8 text", () => {
    // The naive btoa(unescape(encodeURIComponent(s))) idiom this replaced
    // mangles anything outside Latin-1; these are the cases that catch it.
    for (const text of ["hello", "café", "日本語", "🔐 key", ""]) {
      expect(b64ToText(textToB64(text))).toBe(text);
    }
  });

  it("encodes UTF-8 text as its UTF-8 bytes", () => {
    // "é" is two bytes (0xC3 0xA9) in UTF-8, so the encoding must be 4 chars.
    expect(textToB64("é")).toBe("w6k=");
  });

  it("handles a buffer larger than the fromCharCode spread limit", () => {
    // The chunking exists so a large file upload does not blow the argument
    // limit; 100k bytes is comfortably past 0x8000.
    const big = new Uint8Array(100_000);
    for (let i = 0; i < big.length; i++) big[i] = i % 256;
    expect(b64ToBytes(bytesToB64(big))).toEqual(big);
  });

  it("rejects malformed base64 rather than returning garbage", () => {
    expect(isB64("not base64!!")).toBe(false);
    expect(isB64("")).toBe(false);
    expect(isB64("AQ=")).toBe(false); // wrong padding
    expect(isB64("AQID")).toBe(true);
    expect(isB64("  AQID  ")).toBe(true); // operator-pasted whitespace
  });

  it("reports byte length, and -1 when the input does not parse", () => {
    expect(b64Bytes(bytesToB64(new Uint8Array(12)))).toBe(12);
    expect(b64Bytes(bytesToB64(new Uint8Array(32)))).toBe(32);
    expect(b64Bytes("not base64!!")).toBe(-1);
  });

  it("generates the requested number of random bytes", () => {
    expect(b64Bytes(randomB64(12))).toBe(12);
    expect(b64Bytes(randomB64(32))).toBe(32);
  });

  it("does not repeat a generated nonce", () => {
    // Nonce reuse under the same AEAD key is catastrophic, so the generator
    // must be crypto.getRandomValues and not a counter or Math.random.
    const seen = new Set(Array.from({ length: 50 }, () => randomB64(12)));
    expect(seen.size).toBe(50);
  });

  it("throws on decode of invalid input so callers cannot silently proceed", () => {
    expect(() => b64ToBytes("not base64!!")).toThrow();
  });
});
