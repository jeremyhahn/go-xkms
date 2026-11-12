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
import type {
  ListKeysResponse,
  ListKeyVersionsResponse,
  KeyVersionStateResponse,
  AllKeyVersionsResponse,
  RotateScopeKeysResponse,
} from "@go-xkms/sdk";

const keysList = vi.fn<() => Promise<ListKeysResponse>>();
const list = vi.fn<(id: string, backend: string) => Promise<ListKeyVersionsResponse>>();
const enable = vi.fn<(id: string, version: number, backend: string) => Promise<KeyVersionStateResponse>>();
const disable = vi.fn<(id: string, version: number, backend: string) => Promise<KeyVersionStateResponse>>();
const retire = vi.fn<(id: string, version: number, backend: string) => Promise<KeyVersionStateResponse>>();
const enableAll = vi.fn<(id: string, backend: string) => Promise<AllKeyVersionsResponse>>();
const disableAll = vi.fn<(id: string, backend: string) => Promise<AllKeyVersionsResponse>>();
const rotateAll = vi.fn<(tenantId?: string) => Promise<RotateScopeKeysResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    keys: { list: keysList, versions: { list, enable, disable, retire, enableAll, disableAll, rotateAll } },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import KeyVersionsView from "../src/views/KeyVersionsView.svelte";

const keys: ListKeysResponse = {
  keys: [
    { key_id: "signer", key_type: "signing", algorithm: "ecdsa-p256", backend: "soft" },
    { key_id: "sealer", key_type: "encryption", algorithm: "aes-256-gcm", backend: "tpm2" },
  ],
  pagination: {},
} as unknown as ListKeysResponse;

const versions: ListKeyVersionsResponse = {
  key_id: "signer",
  backend: "soft",
  current_version: 3,
  versions: [
    { version: 1, state: "enabled", created_at: "2026-01-01T00:00:00Z" },
    { version: 2, state: "disabled", created_at: "2026-02-01T00:00:00Z" },
    { version: 3, state: "enabled", current: true, created_at: "2026-03-01T00:00:00Z" },
  ],
};

async function choose(): Promise<void> {
  render(KeyVersionsView);
  await screen.findByRole("option", { name: "signer (soft)" });
  await fireEvent.change(screen.getByLabelText("Key"), { target: { value: "0" } });
  await screen.findByText("2026-03-01T00:00:00Z");
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  keysList.mockResolvedValue(keys);
  list.mockResolvedValue(versions);
});

describe("KeyVersionsView", () => {
  it("lists the keys and renders one row per version of the chosen key", async () => {
    render(KeyVersionsView);

    expect(await screen.findByRole("option", { name: "signer (soft)" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "sealer (tpm2)" })).toBeInTheDocument();
    expect(list).not.toHaveBeenCalled();

    await fireEvent.change(screen.getByLabelText("Key"), { target: { value: "0" } });

    await waitFor(() => expect(list).toHaveBeenCalledWith("signer", "soft"));
    const rows = await screen.findAllByRole("row");
    // header row + three versions
    expect(rows).toHaveLength(4);
    expect(screen.getByText("2026-01-01T00:00:00Z")).toBeInTheDocument();
    expect(screen.getByText("2026-02-01T00:00:00Z")).toBeInTheDocument();
    expect(screen.getByText("2026-03-01T00:00:00Z")).toBeInTheDocument();
    expect(screen.getByText("disabled")).toBeInTheDocument();
    expect(screen.getAllByText("current")).toHaveLength(1);
  });

  it("enables a disabled version and reloads", async () => {
    enable.mockResolvedValue({ key_id: "signer", version: 2, state: "enabled", changed: true });
    await choose();

    await fireEvent.click(screen.getByRole("button", { name: "Enable version 2" }));

    await waitFor(() => expect(enable).toHaveBeenCalledWith("signer", 2, "soft"));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(toasts.some((t) => t.kind === "success")).toBe(true);
  });

  it("disables an enabled non-current version", async () => {
    disable.mockResolvedValue({ key_id: "signer", version: 1, state: "disabled", changed: true });
    list.mockResolvedValue({
      ...versions,
      versions: [{ version: 2, state: "enabled", created_at: "2026-02-01T00:00:00Z" }, versions.versions[2]],
    });
    await choose();

    await fireEvent.click(screen.getByRole("button", { name: "Disable version 2" }));

    await waitFor(() => expect(disable).toHaveBeenCalledWith("signer", 2, "soft"));
  });

  it("offers no Disable and no Retire on the current version", async () => {
    await choose();

    expect(screen.queryByRole("button", { name: "Disable version 3" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retire version 3" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retire version 2" })).toBeInTheDocument();
  });

  it("retires a version only after a confirm that names it", async () => {
    retire.mockResolvedValue({ key_id: "signer", version: 2, state: "retired", changed: true });
    await choose();

    await fireEvent.click(screen.getByRole("button", { name: "Retire version 2" }));
    expect(await screen.findByText(/version 2 of signer deletes its key material/)).toBeInTheDocument();
    expect(retire).not.toHaveBeenCalled();

    await fireEvent.click(screen.getByRole("button", { name: "Retire" }));

    await waitFor(() => expect(retire).toHaveBeenCalledWith("signer", 2, "soft"));
  });

  it("cancelling the retire confirm calls nothing", async () => {
    await choose();

    await fireEvent.click(screen.getByRole("button", { name: "Retire version 2" }));
    await screen.findByText(/deletes its key material/);
    await fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(screen.queryByText(/deletes its key material/)).not.toBeInTheDocument());
    expect(retire).not.toHaveBeenCalled();
  });

  it("enables and disables all versions and toasts the count", async () => {
    enableAll.mockResolvedValue({ key_id: "signer", state: "enabled", versions: [1, 2], count: 2 });
    disableAll.mockResolvedValue({ key_id: "signer", state: "disabled", versions: [1], count: 1 });
    await choose();

    await fireEvent.click(screen.getByRole("button", { name: "Enable all" }));
    await waitFor(() => expect(enableAll).toHaveBeenCalledWith("signer", "soft"));
    await waitFor(() => expect(toasts.some((t) => t.message.includes("2 versions enabled"))).toBe(true));

    await fireEvent.click(screen.getByRole("button", { name: "Disable all" }));
    await waitFor(() => expect(disableAll).toHaveBeenCalledWith("signer", "soft"));
    await waitFor(() => expect(toasts.some((t) => t.message.includes("1 versions disabled"))).toBe(true));
  });

  it("rotates all keys after a confirm and shows the counts and each failure", async () => {
    rotateAll.mockResolvedValue({
      tenant_id: "default",
      rotated: 3,
      skipped: 1,
      failed: 1,
      results: [
        { backend: "soft", key_id: "signer", state: "rotated", key_version: 4 },
        { backend: "tpm2", key_id: "sealer", state: "failed", error: "tpm busy" },
      ],
    });
    render(KeyVersionsView);
    await screen.findByRole("option", { name: "signer (soft)" });

    await fireEvent.click(screen.getByRole("button", { name: "Rotate all keys" }));
    expect(rotateAll).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole("button", { name: "Rotate" }));

    await waitFor(() => expect(rotateAll).toHaveBeenCalledTimes(1));
    expect(rotateAll.mock.calls[0]).toHaveLength(0);
    expect(await screen.findByText("Rotated: 3")).toBeInTheDocument();
    expect(screen.getByText("Skipped: 1")).toBeInTheDocument();
    expect(screen.getByText("Failed: 1")).toBeInTheDocument();
    expect(screen.getByText("sealer (tpm2): tpm busy")).toBeInTheDocument();
  });

  it("shows an error alert when listing versions fails", async () => {
    list.mockRejectedValue(new Error("versions unavailable"));
    render(KeyVersionsView);
    await screen.findByRole("option", { name: "signer (soft)" });

    await fireEvent.change(screen.getByLabelText("Key"), { target: { value: "0" } });

    expect(await screen.findByText("versions unavailable")).toBeInTheDocument();
  });

  it("toasts a retire error and keeps the row", async () => {
    retire.mockRejectedValue(new Error("retire refused"));
    await choose();

    await fireEvent.click(screen.getByRole("button", { name: "Retire version 2" }));
    await fireEvent.click(await screen.findByRole("button", { name: "Retire" }));

    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "retire refused" }));
    expect(screen.getByText("2026-02-01T00:00:00Z")).toBeInTheDocument();
  });
});
