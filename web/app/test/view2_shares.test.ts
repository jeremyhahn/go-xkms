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
import { render, screen } from "@testing-library/svelte";
import type { ShareStatusResponse } from "@go-xkms/sdk";

const list = vi.fn<() => Promise<{ shares: ShareStatusResponse[]; pagination: unknown }>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ shares: { list } }),
  resetSDKClient: () => {},
}));

import SharesView from "../src/views/SharesView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("SharesView", () => {
  it("renders server_url, share_index and a named group", async () => {
    const share: ShareStatusResponse = {
      server_url: "https://custodian-1.example.com",
      group_id: "grp-1",
      group_name: "Founders",
      share_index: 2,
      purpose: "unseal",
      received_at: "2026-02-01T00:00:00Z",
    };
    list.mockResolvedValue({ shares: [share], pagination: {} });

    render(SharesView);

    expect(await screen.findByText("Founders")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("https://custodian-1.example.com")).toBeInTheDocument();
    expect(screen.getByText("unseal")).toBeInTheDocument();
    expect(screen.getByText("2026-02-01T00:00:00Z")).toBeInTheDocument();
  });

  it("falls back to group_id when no group_name is known", async () => {
    const share: ShareStatusResponse = {
      server_url: "https://custodian-2.example.com",
      group_id: "grp-raw-id",
      share_index: 0,
      received_at: "2026-02-01T00:00:00Z",
    };
    list.mockResolvedValue({ shares: [share], pagination: {} });

    render(SharesView);

    expect(await screen.findByText("grp-raw-id")).toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument(); // purpose is optional
  });

  it("shows the empty state with no shares collected", async () => {
    list.mockResolvedValue({ shares: [], pagination: {} });

    render(SharesView);

    expect(await screen.findByText("No shares collected.")).toBeInTheDocument();
  });

  it("surfaces a load error instead of a blank page", async () => {
    list.mockRejectedValue(new Error("custodian directory unreachable"));

    render(SharesView);

    expect(await screen.findByText("custodian directory unreachable")).toBeInTheDocument();
  });
});
