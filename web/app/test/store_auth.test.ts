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

// lib/auth.ts wires the shared svelte-auth package exactly once and caches
// the result. Getting the "exactly once" part wrong would re-run
// installAuthFetch/installCrossTabSync on every getAuthContext() call —
// double-installing a global fetch interceptor — so idempotency is asserted
// directly against a mocked initAuth().

import { describe, it, expect, beforeEach, vi } from "vitest";

const initAuthMock = vi.fn();
vi.mock("@go-xkms/svelte-auth", () => ({
  initAuth: (opts: unknown) => initAuthMock(opts),
}));

const getSDKClientMock = vi.fn();
vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => getSDKClientMock(),
}));

describe("lib/auth setupAuth / getAuthContext", () => {
  beforeEach(() => {
    vi.resetModules();
    initAuthMock.mockReset();
    getSDKClientMock.mockReset();
  });

  it("wires the auth package once with the xkms storage prefix and API prefixes", async () => {
    const fakeClient = { name: "fake-client" };
    getSDKClientMock.mockReturnValue(fakeClient);
    const fakeContext = { authStore: {}, provider: {} };
    initAuthMock.mockReturnValue(fakeContext);

    const { setupAuth } = await import("../src/lib/auth.ts");
    const ctx = setupAuth();

    expect(ctx).toBe(fakeContext);
    expect(initAuthMock).toHaveBeenCalledOnce();
    expect(initAuthMock).toHaveBeenCalledWith({
      client: fakeClient,
      storagePrefix: "xkms",
      apiPrefixes: ["/api/", "/xkms/"],
    });
  });

  it("does not re-invoke initAuth on a second call, and getAuthContext returns the same cached context", async () => {
    getSDKClientMock.mockReturnValue({});
    initAuthMock.mockReturnValue({ authStore: {}, provider: {} });

    const { setupAuth, getAuthContext } = await import("../src/lib/auth.ts");
    const first = setupAuth();
    const second = getAuthContext();

    expect(second).toBe(first);
    expect(initAuthMock).toHaveBeenCalledOnce();
  });
});
