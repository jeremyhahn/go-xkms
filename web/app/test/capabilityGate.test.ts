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

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, cleanup } from "@testing-library/svelte";
import { createRawSnippet } from "svelte";

const capabilitiesGet = vi.fn();
vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ capabilities: { get: capabilitiesGet } }),
  resetSDKClient: () => {},
}));

import RouteGate from "../src/components/RouteGate.svelte";
import {
  ROUTE_CAPABILITY,
  SUBSYSTEM_OFF,
  capabilitiesStore,
  loadCapabilities,
  resetCapabilities,
  routeOff,
} from "../src/stores/capabilities.svelte.ts";

const child = createRawSnippet(() => ({ render: () => `<p data-testid="gated-child">view</p>` }));

describe("console capability gate (ruling 972 (1))", () => {
  beforeEach(() => {
    cleanup();
    resetCapabilities();
    capabilitiesGet.mockReset();
  });

  it("maps every view that calls a gated route to its capability flag", () => {
    expect(ROUTE_CAPABILITY).toMatchObject({
      ca: "ca_enabled",
      caTcg: "ca_enabled",
      ssh: "ssh_enabled",
      sshTrust: "ssh_enabled",
      sshSign: "ssh_enabled",
      sshKeyImport: "ssh_enabled",
      tenants: "tenants_enabled",
      tenantDetail: "tenants_enabled",
      tenantQuotas: "tenants_enabled",
      tenantEntitlements: "tenants_enabled",
      tenantTpm: "tenants_enabled",
      passwords: "passwords_enabled",
      passwordAccessMode: "passwords_enabled",
      addPasskey: "webauthn_enabled",
    });
    for (const flag of new Set(Object.values(ROUTE_CAPABILITY))) {
      expect(SUBSYSTEM_OFF[flag]?.setting, flag).toBeTruthy();
    }
  });

  it("loads capabilities once and reports a route off only on an explicit false", async () => {
    capabilitiesGet.mockResolvedValue({ ca_enabled: false, ssh_enabled: true });
    await Promise.all([loadCapabilities(), loadCapabilities()]);
    await loadCapabilities();
    expect(capabilitiesGet).toHaveBeenCalledTimes(1);
    expect(routeOff("ca")).toBe(true);
    expect(routeOff("ssh")).toBe(false);
    expect(routeOff("tenants")).toBe(false); // key omitted
    expect(routeOff("dashboard")).toBe(false); // not gated
  });

  it("a failed probe disables nothing", async () => {
    capabilitiesGet.mockRejectedValue(new Error("down"));
    await loadCapabilities();
    expect(capabilitiesStore.caps).toBeNull();
    expect(routeOff("ca")).toBe(false);
  });

  it("renders the disabled state naming the setting instead of the view", async () => {
    capabilitiesGet.mockResolvedValue({ ca_enabled: false });
    await loadCapabilities();
    render(RouteGate, { props: { route: "ca", children: child } });

    const off = await screen.findByTestId("subsystem-off");
    expect(off.textContent).toContain(SUBSYSTEM_OFF.ca_enabled.setting);
    expect(off.textContent).toContain("ca:");
    expect(screen.queryByTestId("gated-child")).toBeNull();
  });

  it("does not mount a gated view before capabilities are known", () => {
    capabilitiesGet.mockReturnValue(new Promise(() => {}));
    void loadCapabilities();
    render(RouteGate, { props: { route: "ssh", children: child } });
    expect(screen.queryByTestId("gated-child")).toBeNull();
  });

  it("renders the view when its subsystem is on, and ungated views always", async () => {
    capabilitiesGet.mockResolvedValue({ ca_enabled: true });
    await loadCapabilities();
    render(RouteGate, { props: { route: "ca", children: child } });
    expect(await screen.findByTestId("gated-child")).toBeTruthy();
    cleanup();
    render(RouteGate, { props: { route: "dashboard", children: child } });
    expect(screen.getByTestId("gated-child")).toBeTruthy();
  });
});
