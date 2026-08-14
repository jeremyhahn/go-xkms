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

// sdkClient.ts is the single auth choke point for the SPA: its token factory
// decides, on every outgoing request, whether to send the Wails desktop
// standalone loopback bearer or a normally-refreshed access token. Getting
// this backwards would silently break desktop standalone auth (or worse,
// leak a stale loopback token to a remote engine), so the factory's
// precedence is asserted directly rather than through an integration test.

import { describe, it, expect, beforeEach, vi } from "vitest";

// vi.mock factories are hoisted above the rest of the module, so anything
// they close over must be created through vi.hoisted() rather than a
// plain top-level declaration.
const { state, FakeXkmsClient, getValidAccessTokenMock, isWailsRuntimeMock } = vi.hoisted(() => {
  interface CapturedOptions {
    baseURL: string;
    token: () => Promise<string>;
  }
  const state: { captured: CapturedOptions | null } = { captured: null };
  class FakeXkmsClient {
    constructor(opts: CapturedOptions) {
      state.captured = opts;
    }
  }
  return {
    state,
    FakeXkmsClient,
    getValidAccessTokenMock: vi.fn<() => Promise<string>>(),
    isWailsRuntimeMock: vi.fn(() => false),
  };
});

vi.mock("@go-xkms/svelte-auth", () => ({
  getValidAccessToken: () => getValidAccessTokenMock(),
}));

vi.mock("@go-xkms/sdk", () => ({
  XkmsClient: FakeXkmsClient,
  isWailsRuntime: () => isWailsRuntimeMock(),
}));

import { getSDKClient, resetSDKClient } from "../src/stores/sdkClient.ts";

describe("sdkClient", () => {
  beforeEach(() => {
    resetSDKClient();
    state.captured = null;
    getValidAccessTokenMock.mockReset();
    delete (window as unknown as Record<string, unknown>).__XKMS_API_BASE_URL__;
    delete (window as unknown as Record<string, unknown>).__XKMS_LOOPBACK_TOKEN__;
  });

  it("creates exactly one client instance across repeated calls", () => {
    const a = getSDKClient();
    const b = getSDKClient();
    expect(a).toBe(b);
  });

  it("resetSDKClient forces a fresh instance on the next call", () => {
    const a = getSDKClient();
    resetSDKClient();
    const b = getSDKClient();
    expect(a).not.toBe(b);
  });

  it("defaults the base URL to the page origin when nothing is injected", () => {
    getSDKClient();
    expect(state.captured!.baseURL).toBe(window.location.origin);
  });

  it("uses the injected desktop base URL when present and non-empty", () => {
    (window as unknown as Record<string, unknown>).__XKMS_API_BASE_URL__ = "https://127.0.0.1:9443";
    getSDKClient();
    expect(state.captured!.baseURL).toBe("https://127.0.0.1:9443");
  });

  it("falls back to the page origin when the injected base URL is an empty string", () => {
    (window as unknown as Record<string, unknown>).__XKMS_API_BASE_URL__ = "";
    getSDKClient();
    expect(state.captured!.baseURL).toBe(window.location.origin);
  });

  it("token factory prefers the loopback token verbatim and never calls the refresher", async () => {
    (window as unknown as Record<string, unknown>).__XKMS_LOOPBACK_TOKEN__ = "loopback-abc123";
    getValidAccessTokenMock.mockResolvedValue("refreshed-should-not-be-used");
    getSDKClient();

    const token = await state.captured!.token();

    expect(token).toBe("loopback-abc123");
    expect(getValidAccessTokenMock).not.toHaveBeenCalled();
  });

  it("token factory falls back to getValidAccessToken when there is no loopback token", async () => {
    getValidAccessTokenMock.mockResolvedValue("refreshed-xyz");
    getSDKClient();

    const token = await state.captured!.token();

    expect(token).toBe("refreshed-xyz");
    expect(getValidAccessTokenMock).toHaveBeenCalledOnce();
  });
});
