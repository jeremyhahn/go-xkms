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

// test/router.test.ts (owned by another agent) covers parseHash() directly.
// This file covers the reactive half: navigateTo() and the hashchange
// listener that keeps routerStore in sync with window.location.hash.

import { describe, it, expect, afterEach } from "vitest";
import { routerStore, navigateTo } from "../src/stores/router.svelte.ts";

function setHash(hash: string): void {
  window.location.hash = hash;
  // jsdom does dispatch 'hashchange' on a hash-changing assignment, but
  // dispatch it explicitly too so the assertion never races that timing.
  window.dispatchEvent(new HashChangeEvent("hashchange"));
}

describe("router store", () => {
  afterEach(() => {
    window.location.hash = "";
  });

  it("navigateTo prefixes a bare path with '#' before setting the hash", () => {
    navigateTo("/keys");
    expect(window.location.hash).toBe("#/keys");
  });

  it("navigateTo leaves an already-hashed path unchanged", () => {
    navigateTo("#/backends");
    expect(window.location.hash).toBe("#/backends");
  });

  it("routerStore reflects a known route after the hash changes", async () => {
    setHash("#/ca");
    expect(routerStore.name).toBe("ca");
    expect(routerStore.hash).toBe("#/ca");
    expect(routerStore.params).toEqual({});
  });

  it("routerStore falls back to not-found for an unrecognized hash", () => {
    setHash("#/does-not-exist");
    expect(routerStore.name).toBe("not-found");
  });
});
