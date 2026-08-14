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
import type { PIVSlotStatus } from "@go-xkms/sdk";

const listSlots = vi.fn<() => Promise<{ slots: PIVSlotStatus[]; page: number; page_size: number; total: number; has_more: boolean }>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ piv: { listSlots } }),
  resetSDKClient: () => {},
}));

import PivView from "../src/views/PivView.svelte";

function slot(over: Partial<PIVSlotStatus> = {}): PIVSlotStatus {
  return {
    slot: "9a",
    name: "PIV Authentication",
    description: "Authenticates the card holder",
    has_cert: true,
    has_key: true,
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("PivView", () => {
  it("renders slot identity, subject and algorithm once loaded", async () => {
    listSlots.mockResolvedValue({
      slots: [slot({ subject: "CN=alice", algorithm: "ecdsa-p256", not_after: "2027-01-01T00:00:00Z" })],
      page: 1,
      page_size: 50,
      total: 1,
      has_more: false,
    });

    render(PivView);

    expect(await screen.findByText("9a · PIV Authentication")).toBeInTheDocument();
    expect(screen.getByText("Authenticates the card holder")).toBeInTheDocument();
    expect(screen.getByText("Subject: CN=alice")).toBeInTheDocument();
    expect(screen.getByText("Algorithm: ecdsa-p256")).toBeInTheDocument();
    expect(screen.getByText("Expires: 2027-01-01T00:00:00Z")).toBeInTheDocument();
  });

  it("shows key/cert badges only when the slot actually holds them", async () => {
    listSlots.mockResolvedValue({
      slots: [slot({ slot: "9c", has_key: false, has_cert: false })],
      page: 1,
      page_size: 50,
      total: 1,
      has_more: false,
    });

    render(PivView);

    await screen.findByText("9c · PIV Authentication");
    expect(screen.queryByText("key")).not.toBeInTheDocument();
    expect(screen.queryByText("cert")).not.toBeInTheDocument();
  });

  it("shows the empty state when no slots are reported", async () => {
    listSlots.mockResolvedValue({ slots: [], page: 1, page_size: 50, total: 0, has_more: false });

    render(PivView);

    expect(await screen.findByText("No PIV slots reported.")).toBeInTheDocument();
  });

  it("surfaces a load error instead of a blank page", async () => {
    listSlots.mockRejectedValue(new Error("smart card reader not present"));

    render(PivView);

    expect(await screen.findByText("smart card reader not present")).toBeInTheDocument();
  });
});
