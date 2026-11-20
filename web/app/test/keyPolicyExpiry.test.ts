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

// Codex P1 on #2200: loading a policy and saving it with Expiry untouched
// must send the stored expires_at exactly, not the date at midnight UTC.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";

const request = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ http: { request } }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({ showToast: () => {} }));

import KeyAccessPolicyView from "../src/views/KeyAccessPolicyView.svelte";

// 2100-01-01T13:37:42Z: a non-midnight expiry, always in the future.
const EXPIRES = 4102444800 + 13 * 3600 + 37 * 60 + 42;
// 2100-02-03T00:00:00Z.
const FEB3 = Math.floor(Date.parse("2100-02-03T00:00:00Z") / 1000);

beforeEach(() => {
  vi.clearAllMocks();
});

async function loadPolicy(): Promise<void> {
  request.mockResolvedValueOnce({
    policy: { key_id: "k1", version: 4, allowed_principals: ["svc-a"], expires_at: EXPIRES },
    timestamp: 1,
  });
  request.mockResolvedValue({ key_id: "k1", policy_version: 5, timestamp: 1 });
  render(KeyAccessPolicyView);
  await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "k1" } });
  await fireEvent.input(screen.getByPlaceholderText("Backend"), { target: { value: "software" } });
  await fireEvent.click(screen.getByRole("button", { name: "Load" }));
  await screen.findByText("Version 4");
}

function savedPolicy(call: number): Record<string, unknown> {
  return request.mock.calls[call]![2].body.policy;
}

describe("KeyAccessPolicyView expiry round trip", () => {
  it("saves a loaded non-midnight expiry unchanged when Expiry is untouched", async () => {
    await loadPolicy();
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    expect(savedPolicy(1).expires_at).toBe(EXPIRES);
  });

  it("keeps the exact expiry across saves until Expiry is changed or cleared", async () => {
    await loadPolicy();
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText("Version 5");
    await fireEvent.input(screen.getByLabelText("Max usage count"), { target: { value: "9" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(3));
    expect(savedPolicy(2)).toMatchObject({ expires_at: EXPIRES, max_usage_count: 9 });

    await fireEvent.input(screen.getByLabelText("Expiry"), { target: { value: "2100-02-03" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(4));
    expect(savedPolicy(3).expires_at).toBe(FEB3);

    await fireEvent.input(screen.getByLabelText("Expiry"), { target: { value: "" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(5));
    expect(savedPolicy(4).expires_at).toBeUndefined();
  });
});
