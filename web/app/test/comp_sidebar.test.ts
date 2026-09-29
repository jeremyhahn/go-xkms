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

// Sidebar's visible() gate is security-visible behaviour: an item whose
// `requires` permission is absent, or whose `capability` flag is off, must
// not render at all (not just be disabled) — the server remains the
// enforcement authority, but the nav must not dangle a link to a screen the
// operator cannot use. We drive this through the REAL session store (via a
// mocked /auth/me) rather than mocking session.svelte.ts, so the test
// exercises the same `can()`/`hasCapability()` code path the component calls.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/svelte";
import type { AuthMeResponse } from "@go-xkms/sdk";

const meMock = vi.fn<() => Promise<AuthMeResponse>>();
vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ auth: { me: meMock } }),
  resetSDKClient: () => {},
}));

import Sidebar from "../src/components/Sidebar.svelte";
import { loadSession, clearSession } from "../src/stores/session.svelte.ts";

describe("Sidebar RBAC and capability gating", () => {
  beforeEach(() => {
    clearSession();
    meMock.mockReset();
    window.location.hash = "";
  });

  it("hides an item whose required permission is absent from the session", async () => {
    meMock.mockResolvedValue({
      subject: "u1",
      permissions: { "keys:list": true }, // backends:list intentionally absent
      capabilities: {},
    });
    await loadSession();
    render(Sidebar);

    await waitFor(() => expect(screen.getByRole("button", { name: /Keys/ })).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /Backends/ })).not.toBeInTheDocument();
  });

  it("shows an item once its required permission is granted", async () => {
    meMock.mockResolvedValue({
      subject: "u1",
      permissions: { "keys:list": true, "backends:list": true },
      capabilities: {},
    });
    await loadSession();
    render(Sidebar);

    await waitFor(() => expect(screen.getByRole("button", { name: /Backends/ })).toBeInTheDocument());
  });

  it("hides a capability-gated item when the server capability flag is false", async () => {
    meMock.mockResolvedValue({
      subject: "u1",
      permissions: {},
      capabilities: { ca: false },
    });
    await loadSession();
    render(Sidebar);

    await waitFor(() => expect(screen.getByText("Overview")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /Certificate Authority/ })).not.toBeInTheDocument();
  });

  it("shows a capability-gated item when the server capability flag is true", async () => {
    meMock.mockResolvedValue({
      subject: "u1",
      permissions: {},
      capabilities: { ca: true },
    });
    await loadSession();
    render(Sidebar);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Certificate Authority/ })).toBeInTheDocument(),
    );
  });

  it("requires BOTH gates to pass for an item that carries a permission and a capability", async () => {
    // SSH requires capability "ssh" AND permission ssh:read. Capability alone
    // must not be enough to show it. Barrier is granted so the section itself
    // still renders and this isn't confounded with "whole section hidden".
    meMock.mockResolvedValue({
      subject: "u1",
      permissions: { "seal:status": true }, // ssh:read intentionally missing
      capabilities: { ssh: true },
    });
    await loadSession();
    render(Sidebar);

    await waitFor(() => expect(screen.getByRole("button", { name: /Barrier/ })).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /^SSH$/ })).not.toBeInTheDocument();
  });

  it("shows an ungated item (Dashboard) even with no session loaded at all", () => {
    render(Sidebar);
    expect(screen.getByRole("button", { name: /Dashboard/ })).toBeInTheDocument();
    // And a gated item stays hidden by default-deny.
    expect(screen.queryByRole("button", { name: /Backends/ })).not.toBeInTheDocument();
  });

  it("hides an entire section heading when every item in it is gated off", async () => {
    meMock.mockResolvedValue({
      subject: "u1",
      permissions: {}, // keys:list and tpm_policies capability both absent
      capabilities: {},
    });
    await loadSession();
    render(Sidebar);

    await waitFor(() => expect(screen.getByText("Overview")).toBeInTheDocument());
    // "Keys & Crypto" has no visible items under this identity.
    expect(screen.queryByText("Keys & Crypto")).not.toBeInTheDocument();
  });
});
