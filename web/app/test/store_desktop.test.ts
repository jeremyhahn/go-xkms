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

// bootstrapDesktop() is the seam between the Wails desktop shell and the
// SPA: in standalone mode it installs a loopback bearer and flips the auth
// store to authenticated so the desktop owner skips the login screen. Both
// the Wails-present and Wails-absent paths, and the standalone-vs-remote
// branch within it, are covered here.

import { describe, it, expect, beforeEach, vi } from "vitest";

const isWailsRuntimeMock = vi.fn<() => boolean>();
vi.mock("@go-xkms/sdk", () => ({
  isWailsRuntime: () => isWailsRuntimeMock(),
}));

const setAuthenticatedMock = vi.fn();
vi.mock("@go-xkms/svelte-auth", () => ({
  setAuthenticated: (tokens: unknown) => setAuthenticatedMock(tokens),
}));

import { bootstrapDesktop } from "../src/lib/desktop.ts";

describe("bootstrapDesktop", () => {
  beforeEach(() => {
    isWailsRuntimeMock.mockReset();
    setAuthenticatedMock.mockReset();
    delete (window as unknown as Record<string, unknown>).go;
    delete window.__XKMS_API_BASE_URL__;
    delete window.__XKMS_LOOPBACK_TOKEN__;
  });

  it("is a no-op in a plain browser (no Wails runtime)", async () => {
    isWailsRuntimeMock.mockReturnValue(false);

    const result = await bootstrapDesktop();

    expect(result).toBe(false);
    expect(window.__XKMS_API_BASE_URL__).toBeUndefined();
    expect(setAuthenticatedMock).not.toHaveBeenCalled();
  });

  it("is a no-op when Wails is detected but the bridge binding is missing", async () => {
    isWailsRuntimeMock.mockReturnValue(true);
    window.go = { main: {} };

    const result = await bootstrapDesktop();

    expect(result).toBe(false);
    expect(setAuthenticatedMock).not.toHaveBeenCalled();
  });

  it("is a no-op when GetConnection rejects or returns malformed JSON", async () => {
    isWailsRuntimeMock.mockReturnValue(true);
    window.go = { main: { bridge: { GetConnection: () => Promise.resolve("not json") } } };

    const result = await bootstrapDesktop();

    expect(result).toBe(false);
    expect(setAuthenticatedMock).not.toHaveBeenCalled();
  });

  it("points the SDK at the engine URL for a remote-mode connection, without authenticating", async () => {
    isWailsRuntimeMock.mockReturnValue(true);
    window.go = {
      main: {
        bridge: {
          GetConnection: () =>
            Promise.resolve(JSON.stringify({ mode: "remote", base_url: "https://engine.example:8443" })),
        },
      },
    };

    const result = await bootstrapDesktop();

    expect(result).toBe(false);
    expect(window.__XKMS_API_BASE_URL__).toBe("https://engine.example:8443");
    expect(window.__XKMS_LOOPBACK_TOKEN__).toBeUndefined();
    expect(setAuthenticatedMock).not.toHaveBeenCalled();
  });

  it("installs the loopback token and authenticates for a standalone connection", async () => {
    isWailsRuntimeMock.mockReturnValue(true);
    window.go = {
      main: {
        bridge: {
          GetConnection: () =>
            Promise.resolve(
              JSON.stringify({ mode: "standalone", base_url: "http://127.0.0.1:9443", token: "lb-tok-1" }),
            ),
        },
      },
    };

    const result = await bootstrapDesktop();

    expect(result).toBe(true);
    expect(window.__XKMS_API_BASE_URL__).toBe("http://127.0.0.1:9443");
    expect(window.__XKMS_LOOPBACK_TOKEN__).toBe("lb-tok-1");
    expect(setAuthenticatedMock).toHaveBeenCalledWith({ access_token: "lb-tok-1" });
  });

  it("does not authenticate a standalone connection that carries no token", async () => {
    isWailsRuntimeMock.mockReturnValue(true);
    window.go = {
      main: {
        bridge: {
          GetConnection: () => Promise.resolve(JSON.stringify({ mode: "standalone", base_url: "" })),
        },
      },
    };

    const result = await bootstrapDesktop();

    expect(result).toBe(false);
    expect(window.__XKMS_LOOPBACK_TOKEN__).toBeUndefined();
    expect(setAuthenticatedMock).not.toHaveBeenCalled();
  });
});
