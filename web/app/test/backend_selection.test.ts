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

// ListKeysHandler and ListPIVSlotsHandler refuse an empty backend (400), so
// Key Versions and PIV Slots list for the backend the operator selected.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";

const backendsList = vi.fn(() => Promise.resolve({ backends: [{ id: "sw" }, { id: "yk" }] }));
const keysList = vi.fn((backend?: string) =>
  Promise.resolve({ keys: [{ key_id: `k-${backend}`, backend }] }),
);
const listSlots = vi.fn((backend?: string) =>
  Promise.resolve({ slots: [{ slot: `9a-${backend}`, name: "auth", backend, has_key: false, has_cert: false }] }),
);

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    backends: { list: backendsList },
    keys: { list: keysList, versions: {} },
    piv: { listSlots },
  }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: () => {},
}));

import KeyVersionsView from "../src/views/KeyVersionsView.svelte";
import PivSlotsView from "../src/views/PivSlotsView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
});

function everyCallNamesABackend(fn: { mock: { calls: unknown[][] } }): void {
  expect(fn.mock.calls.length).toBeGreaterThan(0);
  for (const args of fn.mock.calls) {
    expect(typeof args[0]).toBe("string");
    expect(args[0]).not.toBe("");
  }
}

describe("KeyVersionsView backend selection", () => {
  it("lists the keys of the selected backend", async () => {
    render(KeyVersionsView);
    await waitFor(() => expect(keysList).toHaveBeenCalledWith("sw"));
    await screen.findByRole("option", { name: "k-sw (sw)" });
    await fireEvent.change(screen.getByLabelText("Backend"), { target: { value: "yk" } });
    await waitFor(() => expect(keysList).toHaveBeenCalledWith("yk"));
    await screen.findByRole("option", { name: "k-yk (yk)" });
    expect(screen.queryByRole("option", { name: "k-sw (sw)" })).not.toBeInTheDocument();
    everyCallNamesABackend(keysList);
  });
});

describe("PivSlotsView backend selection", () => {
  it("lists the slots of the selected backend", async () => {
    render(PivSlotsView);
    await waitFor(() => expect(listSlots).toHaveBeenCalledWith("sw"));
    await screen.findByText("9a-sw");
    await fireEvent.change(screen.getByLabelText("Backend"), { target: { value: "yk" } });
    await waitFor(() => expect(listSlots).toHaveBeenCalledWith("yk"));
    await screen.findByText("9a-yk");
    expect(screen.queryByText("9a-sw")).not.toBeInTheDocument();
    everyCallNamesABackend(listSlots);
  });
});
