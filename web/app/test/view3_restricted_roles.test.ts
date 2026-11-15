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

// Multi-operation views stay reachable for a role that holds any one of
// their operations, and each control is gated on its own permission
// (engineering.md: every action reachable by a caller authorized for it).

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/svelte";

const perms = new Set<string>();

vi.mock("../src/stores/session.svelte.ts", () => ({
  can: (r: string, a: string) => perms.has(`${r}:${a}`),
  lacks: (r: string, a: string) => !perms.has(`${r}:${a}`),
  hasCapability: () => true,
}));
vi.mock("../src/stores/sdkClient.ts", () => ({ getSDKClient: () => ({}) }));

import { navSections, itemVisible, type NavItem } from "../src/lib/nav.ts";
import KeyHmacView from "../src/views/KeyHmacView.svelte";
import KeyBatchView from "../src/views/KeyBatchView.svelte";
import KeyLifecycleView from "../src/views/KeyLifecycleView.svelte";

function item(route: string): NavItem {
  const found = navSections.flatMap((s) => s.items).find((i) => i.route === route);
  if (!found) throw new Error(`no nav item ${route}`);
  return found;
}

function grant(...p: string[]): void {
  perms.clear();
  for (const x of p) perms.add(x);
}

const can = (r: string, a: string): boolean => perms.has(`${r}:${a}`);
const anyCap = (): boolean => true;

describe("restricted roles", () => {
  beforeEach(() => perms.clear());

  it.each([
    ["keyHmac", "keys:verify"],
    ["keyHmac", "keys:sign"],
    ["keyBatch", "keys:decrypt"],
    ["keyBatch", "keys:encrypt"],
    ["keyLifecycle", "keys:delete"],
    ["keyLifecycle", "keys:rotate"],
  ])("shows %s to a role holding only %s", (route, perm) => {
    grant(perm);
    expect(itemVisible(item(route), can, anyCap)).toBe(true);
  });

  it.each(["keyHmac", "keyBatch", "keyLifecycle"])("hides %s from a role holding none of its operations", (route) => {
    grant("keys:list");
    expect(itemVisible(item(route), can, anyCap)).toBe(false);
  });

  it("HMAC: a verify-only role can verify but not compute", async () => {
    grant("keys:verify");
    render(KeyHmacView);
    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k1" } });
    await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
    await fireEvent.input(screen.getByLabelText("Data"), { target: { value: "hello" } });
    await fireEvent.input(screen.getByLabelText("MAC"), { target: { value: "abcd" } });
    expect(screen.getByRole("button", { name: "Compute" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Verify" })).toBeEnabled();
  });

  it("Batch Crypto: a decrypt-only role starts in decrypt mode and cannot pick encrypt", () => {
    grant("keys:decrypt");
    render(KeyBatchView);
    expect(screen.getByRole("button", { name: "Decrypt" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Encrypt" })).toBeDisabled();
  });

  it("Key Lifecycle: a delete-only role can revoke but not enable or disable", async () => {
    grant("keys:delete");
    render(KeyLifecycleView);
    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k1" } });
    await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
    await fireEvent.input(screen.getByLabelText("Confirm key ID"), { target: { value: "k1" } });
    expect(screen.getByRole("button", { name: "Enable" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Disable" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeEnabled();
  });
});
