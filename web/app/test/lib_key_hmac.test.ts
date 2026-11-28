// Copyright (c) 2026 go-xkms authors. All rights reserved.
//
// macToB64 reads a MAC typed as hex in any letter case, or as base64.

import { describe, it, expect, vi } from "vitest";

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({}),
  resetSDKClient: () => {},
}));

import { macToB64 } from "../src/lib/keyHmac.ts";

function decoded(b64: string | null): Uint8Array {
  expect(b64).not.toBeNull();
  return Uint8Array.from(atob(b64 as string), (c) => c.charCodeAt(0));
}

const lowerHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const expected = decoded(macToB64(lowerHex));

describe("macToB64", () => {
  it("decodes a lowercase SHA-256 hex MAC to 32 bytes", () => {
    expect(expected.length).toBe(32);
    expect(expected[10]).toBe(0xaa);
  });

  it("decodes an uppercase SHA-256 hex MAC as hex", () => {
    const bytes = decoded(macToB64(lowerHex.toUpperCase()));
    expect(bytes.length).toBe(32);
    expect(bytes).toEqual(expected);
  });

  it("decodes a mixed-case SHA-256 hex MAC as hex", () => {
    const mixed = "00112233445566778899AaBbCcDdEeFf00112233445566778899aAbBcCdDeEfF";
    const bytes = decoded(macToB64(mixed));
    expect(bytes.length).toBe(32);
    expect(bytes).toEqual(expected);
  });

  it("keeps a real base64 MAC as base64", () => {
    const b64 = btoa(String.fromCharCode(...expected));
    expect(macToB64(b64)).toBe(b64);
    expect(decoded(macToB64(b64))).toEqual(expected);
  });

  it("rejects text that is neither hex nor base64", () => {
    expect(macToB64("not a mac!")).toBeNull();
  });
});
