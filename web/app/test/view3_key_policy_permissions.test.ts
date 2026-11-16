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

// The Key Access Policy, Rotation Policy and Key Safety pages gate each
// control on the permission of its own server route (pkg/api/rest/routes.go):
// policy and rotation-policy GET = keys:get, PUT = keys:rotate,
// DELETE = keys:delete; safety GET = keys:get, PUT and DELETE = keys:rotate.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";

const request = vi.fn<(method: string, path: string, opts?: unknown) => Promise<unknown>>();
const perms = vi.hoisted(() => new Set<string>());

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ http: { request } }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: () => {},
}));

vi.mock("../src/stores/session.svelte.ts", async (orig) => ({
  ...(await orig<typeof import("../src/stores/session.svelte.ts")>()),
  can: (resource: string, action: string) => perms.has(`${resource}:${action}`),
}));

import KeyAccessPolicyView from "../src/views/KeyAccessPolicyView.svelte";
import KeyRotationPolicyView from "../src/views/KeyRotationPolicyView.svelte";
import KeySafetyView from "../src/views/KeySafetyView.svelte";

let confirmSpy: { mockRestore(): void } | undefined;

function grant(...p: string[]): void {
  perms.clear();
  for (const x of p) perms.add(x);
}

function button(name: string): HTMLElement {
  return screen.getByRole("button", { name });
}

function methods(): string[] {
  return request.mock.calls.map((c) => c[0]);
}

async function selectKey(): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k1" } });
  await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "pkcs8" } });
}

beforeEach(() => {
  vi.clearAllMocks();
  request.mockImplementation((_method, path) =>
    Promise.resolve(path === "/api/v1/safety/report" ? { all_items: [], timestamp: 1 } : { key_id: "k1", warnings: [], timestamp: 1 }),
  );
  confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
});

afterEach(() => {
  confirmSpy?.mockRestore();
});

describe.each([
  ["Key Access Policy", KeyAccessPolicyView, "Remove policy"],
  ["Rotation Policy", KeyRotationPolicyView, "Remove"],
])("%s per-operation gating", (_name, View, removeLabel) => {
  it("lets a keys:rotate-only caller save without keys:get", async () => {
    grant("keys:rotate");
    render(View);
    await selectKey();
    if (View === KeyRotationPolicyView) {
      await fireEvent.input(screen.getByLabelText("Interval"), { target: { value: "24" } });
    }
    expect(button("Load")).toBeDisabled();
    expect(button(removeLabel)).toBeDisabled();
    expect(button("Save")).toBeEnabled();
    await fireEvent.click(button("Save"));
    await waitFor(() => expect(methods()).toEqual(["PUT"]));
  });

  it("lets a keys:delete-only caller remove the policy", async () => {
    grant("keys:delete");
    render(View);
    await selectKey();
    expect(button("Load")).toBeDisabled();
    expect(button("Save")).toBeDisabled();
    expect(button(removeLabel)).toBeEnabled();
    await fireEvent.click(button(removeLabel));
    await waitFor(() => expect(methods()).toEqual(["DELETE"]));
  });

  it("lets a keys:get-only caller load but not change the policy", async () => {
    grant("keys:get");
    render(View);
    await selectKey();
    expect(button("Load")).toBeEnabled();
    expect(button("Save")).toBeDisabled();
    expect(button(removeLabel)).toBeDisabled();
  });
});

describe("Key Safety per-operation gating", () => {
  it("lets a keys:rotate-only caller set and clear limits without loading the report", async () => {
    grant("keys:rotate");
    render(KeySafetyView);
    await selectKey();
    expect(button("Set limits")).toBeEnabled();
    expect(button("Clear limits")).toBeEnabled();
    await fireEvent.click(button("Set limits"));
    await waitFor(() => expect(methods()).toEqual(["PUT"]));
    await fireEvent.click(button("Clear limits"));
    await waitFor(() => expect(methods()).toEqual(["PUT", "DELETE"]));
  });

  it("disables Set and Clear limits for a caller without keys:rotate", async () => {
    grant("keys:get");
    render(KeySafetyView);
    await selectKey();
    expect(button("Set limits")).toBeDisabled();
    expect(button("Clear limits")).toBeDisabled();
    await waitFor(() => expect(methods()).toEqual(["GET", "GET"]));
  });
});
