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
import { render, screen, waitFor } from "@testing-library/svelte";
import type { ListBackendsResponse } from "@go-xkms/sdk";

const list = vi.fn<() => Promise<ListBackendsResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ backends: { list } }),
  resetSDKClient: () => {},
}));

import BackendsView from "../src/views/BackendsView.svelte";

const caps = {
  Keys: true,
  HardwareBacked: true,
  Signing: true,
  Decryption: true,
  KeyRotation: true,
  SymmetricEncryption: true,
  Sealing: false,
  Import: true,
  Export: true,
  KeyAgreement: true,
  ECIES: false,
  Attestation: true,
  QuantumSigning: false,
  KeyEncapsulation: false,
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("BackendsView", () => {
  it("shows a loading spinner then the resolved backends", async () => {
    list.mockResolvedValue({
      backends: [
        { id: "tpm-0", type: "tpm2", hardware_backed: true, capabilities: caps },
        { id: "sw-0", type: "software", hardware_backed: false, capabilities: caps },
      ],
      pagination: { page: 1, page_size: 50, total: 2, has_more: false },
    });

    render(BackendsView);

    expect(document.querySelector(".loading-spinner")).not.toBeNull();

    await waitFor(() => expect(screen.getByText("tpm-0")).toBeInTheDocument());
    expect(screen.getByText("sw-0")).toBeInTheDocument();
    expect(screen.getByText("tpm2")).toBeInTheDocument();
    expect(screen.getByText("software")).toBeInTheDocument();
    // hardware_backed is rendered as a yes/no column, not the raw boolean.
    expect(screen.getByText("yes")).toBeInTheDocument();
    expect(screen.getByText("no")).toBeInTheDocument();
  });

  it("shows the empty message when no backends are configured", async () => {
    list.mockResolvedValue({ backends: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });

    render(BackendsView);

    expect(await screen.findByText("No backends configured.")).toBeInTheDocument();
  });

  it("surfaces the error instead of an empty table on failure", async () => {
    list.mockRejectedValue(new Error("backend registry unavailable"));

    render(BackendsView);

    expect(await screen.findByText("backend registry unavailable")).toBeInTheDocument();
    expect(screen.queryByText("No backends configured.")).toBeNull();
  });
});
