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

// test/session.test.ts (owned by another agent) covers the primary can()/
// hasCapability() gating paths. This file covers the identity-fallback
// getters and the non-Error rejection branch that suite does not exercise.

import { describe, it, expect, beforeEach, vi } from "vitest";
import type { AuthMeResponse } from "@go-xkms/sdk";

const meMock = vi.fn<() => Promise<AuthMeResponse>>();
vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ auth: { me: meMock } }),
  resetSDKClient: () => {},
}));

import { sessionStore, loadSession, clearSession } from "../src/stores/session.svelte.ts";

describe("session store identity fallbacks", () => {
  beforeEach(() => {
    clearSession();
    meMock.mockReset();
  });

  it("falls all the way back to subject when neither display_name nor username is present", async () => {
    meMock.mockResolvedValue({ subject: "sub-1", permissions: {}, capabilities: {} });
    await loadSession();

    expect(sessionStore.username).toBe("sub-1");
    expect(sessionStore.displayName).toBe("sub-1");
  });

  it("prefers username over subject, and display_name over username", async () => {
    meMock.mockResolvedValue({
      subject: "sub-1",
      username: "bob",
      display_name: "Bob B",
      permissions: {},
      capabilities: {},
    });
    await loadSession();

    expect(sessionStore.username).toBe("bob");
    expect(sessionStore.displayName).toBe("Bob B");
  });

  it("defaults roles to an empty array and capabilities to an empty object when absent", async () => {
    meMock.mockResolvedValue({ subject: "sub-1", permissions: {}, capabilities: {} } as AuthMeResponse);
    await loadSession();

    expect(sessionStore.roles).toEqual([]);
    expect(sessionStore.capabilities).toEqual({});
  });

  it("stringifies a non-Error rejection instead of throwing", async () => {
    meMock.mockRejectedValue("plain string failure");
    await loadSession();

    expect(sessionStore.error).toBe("plain string failure");
    expect(sessionStore.me).toBeNull();
  });

  it("has no identity before any session has been loaded", () => {
    expect(sessionStore.username).toBe("");
    expect(sessionStore.displayName).toBe("");
    expect(sessionStore.roles).toEqual([]);
    expect(sessionStore.capabilities).toEqual({});
    expect(sessionStore.loading).toBe(false);
  });
});
