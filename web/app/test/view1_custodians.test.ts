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
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { ListCustodianGroupsResponse } from "@go-xkms/sdk";

const listGroups = vi.fn<() => Promise<ListCustodianGroupsResponse>>();
const distributeShares = vi.fn<(id: string) => Promise<{ distributed: number }>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ custodian: { listGroups, distributeShares } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import CustodiansView from "../src/views/CustodiansView.svelte";

const group = {
  id: "grp-1",
  name: "Recovery Officers",
  purpose: "root key recovery",
  threshold: 3,
  total: 5,
  members: [
    { share_index: 0, user_id: "u1", username: "alice", assigned_at: "2026-01-01T00:00:00Z", method: "share" },
    { share_index: 1, user_id: "u2", username: "bob", assigned_at: "2026-01-01T00:00:00Z", method: "share" },
  ],
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("CustodiansView", () => {
  it("shows a loading spinner then the resolved custodian groups with threshold-of-total", async () => {
    listGroups.mockResolvedValue({ groups: [group], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });

    render(CustodiansView);
    expect(document.querySelector(".loading-spinner")).not.toBeNull();

    await waitFor(() => expect(screen.getByText("Recovery Officers")).toBeInTheDocument());
    // CustodianGroupInfo.threshold / .total render as "N-of-M", the exact
    // wire fields this view is built around.
    expect(screen.getByText("3-of-5")).toBeInTheDocument();
    expect(screen.getByText("2 members")).toBeInTheDocument();
  });

  it("shows the empty-groups hint when there are none", async () => {
    listGroups.mockResolvedValue({ groups: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });

    render(CustodiansView);

    expect(
      await screen.findByText((_, node) => node?.textContent === "No custodian groups. Create one with xkmsctl custodian create."),
    ).toBeInTheDocument();
  });

  it("surfaces a list error", async () => {
    listGroups.mockRejectedValue(new Error("custodian service unavailable"));

    render(CustodiansView);

    expect(await screen.findByText("custodian service unavailable")).toBeInTheDocument();
  });

  it("distributes shares for the exact group id and reloads on success", async () => {
    listGroups.mockResolvedValue({ groups: [group], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });
    distributeShares.mockResolvedValue({ distributed: 5 });

    render(CustodiansView);
    await screen.findByText("Recovery Officers");
    await fireEvent.click(screen.getByRole("button", { name: "Distribute shares" }));

    await waitFor(() => expect(distributeShares).toHaveBeenCalledWith("grp-1"));
    expect(toasts).toContainEqual({ kind: "success", message: "Shares distributed." });
    await waitFor(() => expect(listGroups).toHaveBeenCalledTimes(2));
  });

  it("toasts an error and does not reload when distribution fails", async () => {
    listGroups.mockResolvedValue({ groups: [group], pagination: { page: 1, page_size: 50, total: 1, has_more: false } });
    distributeShares.mockRejectedValue(new Error("quorum not met"));

    render(CustodiansView);
    await screen.findByText("Recovery Officers");
    await fireEvent.click(screen.getByRole("button", { name: "Distribute shares" }));

    await waitFor(() =>
      expect(toasts).toContainEqual({ kind: "error", message: "quorum not met" }),
    );
    expect(listGroups).toHaveBeenCalledTimes(1);
  });
});
