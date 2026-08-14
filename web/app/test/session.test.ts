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

import { describe, it, expect, beforeEach, vi } from "vitest";
import type { AuthMeResponse } from "@go-xkms/sdk";

// Mock the SDK client singleton so the session store resolves against a fake
// /auth/me response instead of the network.
const meMock = vi.fn<() => Promise<AuthMeResponse>>();
vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ auth: { me: meMock } }),
  resetSDKClient: () => {},
}));

import {
  sessionStore,
  loadSession,
  clearSession,
  can,
  hasCapability,
} from "../src/stores/session.svelte.ts";

const sampleMe: AuthMeResponse = {
  subject: "user-1",
  username: "alice",
  display_name: "Alice Admin",
  roles: ["admin"],
  permissions: {
    "keys:list": true,
    "keys:create": false,
  },
  capabilities: {
    ca: true,
    cluster: false,
  },
};

describe("session store", () => {
  beforeEach(() => {
    clearSession();
    meMock.mockReset();
  });

  it("populates identity, permissions and capabilities from /auth/me", async () => {
    meMock.mockResolvedValue(sampleMe);
    await loadSession();

    expect(sessionStore.me).not.toBeNull();
    expect(sessionStore.username).toBe("alice");
    expect(sessionStore.displayName).toBe("Alice Admin");
    expect(sessionStore.roles).toEqual(["admin"]);
    expect(sessionStore.error).toBeNull();
  });

  it("gates can() on the permission map", async () => {
    meMock.mockResolvedValue(sampleMe);
    await loadSession();

    expect(can("keys", "list")).toBe(true);
    expect(can("keys", "create")).toBe(false);
    // A permission absent from the map is denied.
    expect(can("tenants", "list")).toBe(false);
  });

  it("gates hasCapability() on the capability map", async () => {
    meMock.mockResolvedValue(sampleMe);
    await loadSession();

    expect(hasCapability("ca")).toBe(true);
    expect(hasCapability("cluster")).toBe(false);
    expect(hasCapability("unknown")).toBe(false);
  });

  it("denies everything when no session is loaded", () => {
    clearSession();
    expect(can("keys", "list")).toBe(false);
    expect(hasCapability("ca")).toBe(false);
  });

  it("records an error and clears identity when /auth/me fails", async () => {
    meMock.mockRejectedValue(new Error("unauthorized"));
    await loadSession();

    expect(sessionStore.me).toBeNull();
    expect(sessionStore.error).toBe("unauthorized");
    expect(can("keys", "list")).toBe(false);
  });
});
