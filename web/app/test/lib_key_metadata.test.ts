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

import { describe, it, expect, vi } from "vitest";

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ http: { request: vi.fn() } }),
  resetSDKClient: () => {},
}));

import { diffMetadata } from "../src/lib/keyMetadata.ts";

const base = { name: "n", description: "d" };

describe("diffMetadata", () => {
  it("diffs tags named like inherited object properties as own tags", () => {
    const before = { ...base, tags: { constructor: "a", toString: "b", env: "prod" } };
    const after = { ...base, tags: { env: "prod", hasOwnProperty: "y" } };
    expect(diffMetadata(before, after)).toEqual({
      tags: { hasOwnProperty: "y" },
      remove_tags: ["constructor", "toString"],
    });
    expect(diffMetadata(after, { ...after, tags: { ...after.tags } })).toEqual({});
  });

  it("returns a changed __proto__ tag as an own property of the tags map", () => {
    const before = { ...base, tags: JSON.parse('{"__proto__":"a"}') as Record<string, string> };
    const after = { ...base, tags: JSON.parse('{"__proto__":"b"}') as Record<string, string> };
    const changes = diffMetadata(before, after);
    expect(Object.hasOwn(changes.tags ?? {}, "__proto__")).toBe(true);
    expect(JSON.stringify(changes)).toBe('{"tags":{"__proto__":"b"}}');
  });
});
