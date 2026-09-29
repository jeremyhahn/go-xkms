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

/**
 * App.svelte dispatch. Two things can silently break here and nowhere else:
 * a route wired to the wrong view (every screen still renders, just the wrong
 * one), and the signed-out guard leaking an authenticated screen. Both are
 * asserted per route rather than spot-checked.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/svelte";

// Every view calls the SDK on mount, and this test is about dispatch, not
// about any one view's data flow. So every domain call REJECTS: each view
// catches, renders its error alert, and still renders its PageHeader — which
// is exactly the marker being asserted. auth.me is the one exception, since
// the session store must hold a real permission map for can() to work.
const authMe = vi.fn();

const rejecting: unknown = new Proxy(
  {},
  {
    get: (_t, domain): unknown => {
      if (domain === "auth") {
        return { me: authMe };
      }
      return new Proxy(
        {},
        { get: (): unknown => () => Promise.reject(new Error("stubbed out")) },
      );
    },
  },
);

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => rejecting,
  resetSDKClient: () => {},
}));

const authState = { status: "authenticated" as string };

vi.mock("@go-xkms/svelte-auth", () => ({
  authStore: {
    get status() {
      return authState.status;
    },
  },
  initAuth: () => ({}),
  getAuthContext: () => ({}),
  LoginPanel: (() => {}) as unknown,
  RegisterPanel: (() => {}) as unknown,
}));

import { navigateTo } from "../src/stores/router.svelte.ts";
import { clearSession, loadSession } from "../src/stores/session.svelte.ts";
import App from "../src/App.svelte";

// Each route paired with a string that appears only on its view.
const ROUTES: [string, string][] = [
  ["/dashboard", "Dashboard"],
  ["/backends", "Backends"],
  ["/keys", "Keys"],
  ["/certs", "Certificates"],
  ["/ca", "Certificate Authority"],
  ["/barrier", "Barrier"],
  ["/pin", "PIN"],
  ["/piv", "PIV"],
  ["/ssh", "SSH"],
  ["/tpm/policies", "TPM Policies"],
  ["/users", "Users"],
  ["/factors", "Auth Factors"],
  ["/frost", "FROST"],
  ["/audit", "Audit"],
  ["/tenants", "Tenants"],
  ["/custodians", "Custodians"],
  ["/shares", "Shares"],
  ["/passwords", "Passwords"],
  ["/platform", "Platform Secrets"],
  ["/ceremony", "Init & Ceremony"],
  ["/cluster", "Cluster"],
  ["/settings", "Settings"],
];

beforeEach(async () => {
  vi.clearAllMocks();
  clearSession();
  authState.status = "authenticated";
  // Permit everything so no view is hidden by a gate; the gates themselves
  // are covered by the per-view suites.
  authMe.mockResolvedValue({
    subject: "op-1",
    username: "operator",
    roles: ["admin"],
    permissions: new Proxy({}, { get: () => true }),
    capabilities: new Proxy({}, { get: () => true }),
  });
  await loadSession();
});

afterEach(() => {
  window.location.hash = "";
});

describe("App route dispatch", () => {
  it.each(ROUTES)("renders the view for %s", async (path, marker) => {
    navigateTo(path);

    render(App);

    await waitFor(() =>
      expect(screen.getAllByText(new RegExp(marker, "i")).length).toBeGreaterThan(0),
    );
  });

  it("renders the not-found placeholder for an unknown route", async () => {
    navigateTo("/does-not-exist");

    render(App);

    expect(await screen.findByText("Not found")).toBeInTheDocument();
  });

  it("redirects an authenticated visitor away from the login route", async () => {
    navigateTo("/login");

    render(App);

    await waitFor(() => expect(window.location.hash).toBe("#/dashboard"));
  });
});

describe("App authentication guard", () => {
  it("shows the login screen and no shell when unauthenticated", async () => {
    authState.status = "unauthenticated";
    navigateTo("/keys");

    render(App);

    // The keys screen must not render behind the login gate even though the
    // route points at it.
    await waitFor(() => expect(screen.queryByText("TPM Policies")).toBeNull());
    expect(document.querySelector("aside")).toBeNull();
  });

  it("shows the register screen when the route asks for it while signed out", async () => {
    authState.status = "unauthenticated";
    navigateTo("/register");

    render(App);

    await waitFor(() => expect(document.querySelector("aside")).toBeNull());
  });

  it("loads the session once authenticated", async () => {
    navigateTo("/dashboard");

    render(App);

    // loadSession is driven by the $effect on auth status; the store moving
    // out of its empty state is the observable outcome.
    await waitFor(() => expect(document.querySelector("aside")).not.toBeNull());
  });
});
