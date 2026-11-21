/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of go-xkms.
 *
 * go-xkms is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

// Ruling 972 (1): no console view may lead to a 501 / "not configured"
// state. A view whose routes the server does not serve renders a disabled
// state naming the setting instead of mounting (and calling the route).
// The flags come from the authenticated session (/auth/me capabilities);
// the public /api/v1/capabilities stays coarse so an anonymous caller
// cannot fingerprint the deployment.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, cleanup } from "@testing-library/svelte";
import { createRawSnippet } from "svelte";

const me = vi.fn();
const capabilitiesGet = vi.fn();
vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ auth: { me }, capabilities: { get: capabilitiesGet } }),
  resetSDKClient: () => {},
}));

import RouteGate from "../src/components/RouteGate.svelte";
import { ROUTE_CAPABILITY, SUBSYSTEM_OFF, routeOff, routePending } from "../src/stores/capabilities.svelte.ts";
import { clearSession, loadSession } from "../src/stores/session.svelte.ts";

const child = createRawSnippet(() => ({ render: () => `<p data-testid="gated-child">view</p>` }));

function session(capabilities: Record<string, boolean>) {
  return { subject: "op", roles: [], permissions: {}, capabilities };
}

describe("console capability gate (ruling 972 (1))", () => {
  beforeEach(() => {
    cleanup();
    clearSession();
    me.mockReset();
    capabilitiesGet.mockReset();
  });

  it("maps every view that calls a gated route to its /auth/me capability", () => {
    expect(ROUTE_CAPABILITY).toMatchObject({
      ca: "ca",
      caTcg: "ca",
      ssh: "ssh",
      sshTrust: "ssh",
      sshSign: "ssh",
      sshKeyImport: "ssh",
      tenants: "tenants",
      tenantDetail: "tenants",
      tenantQuotas: "tenants",
      tenantEntitlements: "tenants",
      tenantTpm: "tenants",
      passwords: "passwords",
      passwordAccessMode: "passwords",
      addPasskey: "webauthn",
    });
    for (const flag of new Set(Object.values(ROUTE_CAPABILITY))) {
      expect(SUBSYSTEM_OFF[flag]?.setting, flag).toBeTruthy();
    }
  });

  it("reads the session's flags, not the public capabilities, and gates only on an explicit false", async () => {
    me.mockResolvedValue(session({ ca: false, ssh: true }));
    await loadSession();
    expect(capabilitiesGet).not.toHaveBeenCalled();
    expect(routeOff("ca")).toBe(true);
    expect(routeOff("ssh")).toBe(false);
    expect(routeOff("tenants")).toBe(false); // key omitted
    expect(routeOff("dashboard")).toBe(false); // not gated
  });

  it("a failed session load disables nothing and does not hold the view", async () => {
    me.mockRejectedValue(new Error("down"));
    await loadSession();
    expect(routeOff("ca")).toBe(false);
    expect(routePending("ca")).toBe(false);
  });

  it("renders the disabled state naming the setting instead of the view", async () => {
    me.mockResolvedValue(session({ ca: false }));
    await loadSession();
    render(RouteGate, { props: { route: "ca", children: child } });

    const off = await screen.findByTestId("subsystem-off");
    expect(off.textContent).toContain(SUBSYSTEM_OFF.ca.setting);
    expect(off.textContent).toContain("ca:");
    expect(screen.queryByTestId("gated-child")).toBeNull();
  });

  it("does not mount a gated view before the session is known", () => {
    me.mockReturnValue(new Promise(() => {}));
    void loadSession();
    render(RouteGate, { props: { route: "ssh", children: child } });
    expect(screen.queryByTestId("gated-child")).toBeNull();
  });

  it("renders the view when its subsystem is on, and ungated views always", async () => {
    me.mockResolvedValue(session({ ca: true }));
    await loadSession();
    render(RouteGate, { props: { route: "ca", children: child } });
    expect(await screen.findByTestId("gated-child")).toBeTruthy();
    cleanup();
    render(RouteGate, { props: { route: "dashboard", children: child } });
    expect(screen.getByTestId("gated-child")).toBeTruthy();
  });
});
