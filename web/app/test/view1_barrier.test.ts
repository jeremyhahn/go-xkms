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
import type { BarrierStatusResponse } from "@go-xkms/sdk";

const status = vi.fn<() => Promise<BarrierStatusResponse>>();
const unseal = vi.fn();
const seal = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ barrier: { status, unseal, seal } }),
  resetSDKClient: () => {},
}));

// can() gates the unseal/seal controls; this test file drives it explicitly
// per-test rather than going through a full session load.
const canMock = vi.fn<(resource: string, action: string) => boolean>();
vi.mock("../src/stores/session.svelte.ts", () => ({
  can: (resource: string, action: string) => canMock(resource, action),
  hasCapability: () => false,
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import BarrierView from "../src/views/BarrierView.svelte";

const sealedStatus: BarrierStatusResponse = {
  sealed: true,
  strategy: "shamir",
  hardware_backed: true,
  initialized_at: "2026-01-01T00:00:00Z",
};

const unsealedStatus: BarrierStatusResponse = {
  sealed: false,
  strategy: "shamir",
  hardware_backed: false,
  initialized_at: "2026-01-01T00:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  canMock.mockReturnValue(true);
});

describe("BarrierView", () => {
  it("shows a loading spinner then the resolved status", async () => {
    status.mockResolvedValue(unsealedStatus);
    render(BarrierView);

    expect(document.querySelector(".loading-spinner")).not.toBeNull();

    await waitFor(() => expect(screen.getByText("unsealed")).toBeInTheDocument());
    expect(screen.getByText("strategy: shamir")).toBeInTheDocument();
  });

  it("surfaces a status error", async () => {
    status.mockRejectedValue(new Error("barrier status unavailable"));
    render(BarrierView);

    expect(await screen.findByText("barrier status unavailable")).toBeInTheDocument();
  });

  it("hides the unseal form when the operator lacks seal:unseal", async () => {
    canMock.mockImplementation((_r, action) => action !== "unseal");
    status.mockResolvedValue(sealedStatus);
    render(BarrierView);

    await screen.findByText("sealed");
    expect(screen.queryByRole("button", { name: "Unseal" })).toBeNull();
  });

  it("shows the unseal form and sends only `secret` in the request", async () => {
    status.mockResolvedValue(sealedStatus);
    unseal.mockResolvedValue(undefined);
    render(BarrierView);

    await screen.findByText("sealed");
    const passphraseInput = screen.getByLabelText("Passphrase") as HTMLInputElement;
    await fireEvent.input(passphraseInput, { target: { value: "correct horse battery" } });

    status.mockResolvedValue(unsealedStatus);
    await fireEvent.click(screen.getByRole("button", { name: "Unseal" }));

    await waitFor(() => expect(unseal).toHaveBeenCalledOnce());
    // BarrierUnsealRequest.secret is the wire field — pin it exactly, no
    // stray password_b64 or extra keys.
    expect(unseal.mock.calls[0]![0]).toEqual({ secret: "correct horse battery" });
    expect(toasts).toContainEqual({ kind: "success", message: "Barrier unsealed." });
  });

  it("toasts an error and leaves the barrier sealed when unseal fails", async () => {
    status.mockResolvedValue(sealedStatus);
    unseal.mockRejectedValue(new Error("wrong passphrase"));
    render(BarrierView);

    await screen.findByText("sealed");
    await fireEvent.click(screen.getByRole("button", { name: "Unseal" }));

    await waitFor(() =>
      expect(toasts).toContainEqual({ kind: "error", message: "wrong passphrase" }),
    );
  });

  it("shows the seal button only when unsealed and permitted, and seals on click", async () => {
    status.mockResolvedValue(unsealedStatus);
    seal.mockResolvedValue(undefined);
    render(BarrierView);

    const sealBtn = await screen.findByRole("button", { name: "Seal barrier" });
    status.mockResolvedValue(sealedStatus);
    await fireEvent.click(sealBtn);

    await waitFor(() => expect(seal).toHaveBeenCalledOnce());
    expect(toasts).toContainEqual({ kind: "success", message: "Barrier sealed." });
  });

  it("hides the seal button when the operator lacks seal:seal", async () => {
    canMock.mockImplementation((_r, action) => action !== "seal");
    status.mockResolvedValue(unsealedStatus);
    render(BarrierView);

    await screen.findByText("unsealed");
    expect(screen.queryByRole("button", { name: "Seal barrier" })).toBeNull();
  });
});
